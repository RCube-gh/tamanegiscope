from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
import mimetypes
import re
import socket
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app.config import SCAN_TIMEOUT_MS, TOR_SOCKS_URL, artifact_root
from app.models import ArtifactInfo, NetworkMode, QuickScanRequest, QuickScanResult, ScanArtifacts


class TargetValidationError(ValueError):
    pass


class ScanNotFoundError(FileNotFoundError):
    pass


SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
POST_LOAD_SETTLE_MS = 500
LAZY_SCROLL_PAUSE_MS = 250
MAX_LAZY_SCROLL_STEPS = 30


def scan_directory(scan_id: str) -> Path:
    """Resolve a scan directory without allowing path traversal."""
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise ScanNotFoundError(scan_id)

    directory = artifact_root() / scan_id
    if not directory.is_dir():
        raise ScanNotFoundError(scan_id)
    return directory


def load_scan_result(scan_id: str) -> QuickScanResult:
    metadata = scan_directory(scan_id) / "metadata.json"
    try:
        data = json.loads(metadata.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ScanNotFoundError(scan_id) from error
    data.pop("created_at", None)
    return QuickScanResult.model_validate(data)


def load_scan_summary(scan_id: str) -> dict[str, Any]:
    summary = scan_directory(scan_id) / "summary.json"
    try:
        return json.loads(summary.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ScanNotFoundError(scan_id) from error


def list_artifacts(scan_id: str) -> ScanArtifacts:
    directory = scan_directory(scan_id)
    artifacts = []
    for path in directory.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        artifacts.append(
            ArtifactInfo(
                name=path.relative_to(directory).as_posix(),
                size_bytes=path.stat().st_size,
                media_type=mimetypes.guess_type(path.name)[0],
            )
        )
    return ScanArtifacts(scan_id=scan_id, artifacts=sorted(artifacts, key=lambda artifact: artifact.name))


def scan_artifact(scan_id: str, name: str) -> Path:
    directory = scan_directory(scan_id).resolve()
    path = (directory / name).resolve()
    if directory not in path.parents or not path.is_file() or path.is_symlink():
        raise ScanNotFoundError(scan_id)
    return path


def redacted_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "[redacted]" if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def write_json(path: Path, contents: Any) -> None:
    path.write_text(json.dumps(contents, ensure_ascii=False, indent=2), encoding="utf-8")


def hostname(value: str) -> str | None:
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None


def build_scan_summary(
    result: QuickScanResult,
    network_events: dict[str, list[dict[str, Any]]],
    redirects: list[dict[str, Any]],
    console_messages: list[dict[str, Any]],
    page_errors: list[dict[str, str]],
    downloads: list[dict[str, Any]],
) -> dict[str, Any]:
    domain_data: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"requests": 0, "responses": 0, "failed": 0, "ips": set(), "statuses": Counter()}
    )
    ip_data: dict[str, dict[str, Any]] = defaultdict(lambda: {"responses": 0, "domains": set()})
    resource_types = Counter()
    status_codes = Counter()

    for entry in network_events["requests"]:
        target = hostname(entry["url"])
        resource_types[entry.get("resource_type", "other")] += 1
        if target:
            domain_data[target]["requests"] += 1

    for entry in network_events["responses"]:
        target = hostname(entry["url"])
        status = entry.get("status")
        if status is not None:
            status_codes[str(status)] += 1
        if not target:
            continue
        domain_data[target]["responses"] += 1
        if status is not None:
            domain_data[target]["statuses"][str(status)] += 1
        address = entry.get("server_address") or {}
        ip = address.get("ipAddress") if isinstance(address, dict) else None
        if ip:
            domain_data[target]["ips"].add(ip)
            ip_data[ip]["responses"] += 1
            ip_data[ip]["domains"].add(target)

    for entry in network_events["failed_requests"]:
        target = hostname(entry["url"])
        if target:
            domain_data[target]["failed"] += 1

    domains = [
        {
            "domain": domain,
            "requests": values["requests"],
            "responses": values["responses"],
            "failed": values["failed"],
            "ips": sorted(values["ips"]),
            "statuses": dict(sorted(values["statuses"].items())),
        }
        for domain, values in domain_data.items()
    ]
    domains.sort(key=lambda item: (-item["requests"], item["domain"]))
    ips = [
        {"ip": ip, "responses": values["responses"], "domains": sorted(values["domains"])}
        for ip, values in ip_data.items()
    ]
    ips.sort(key=lambda item: (-item["responses"], item["ip"]))
    primary_response = next(
        (entry for entry in reversed(network_events["responses"]) if entry["url"] == result.final_url), None
    )

    return {
        "scan_id": result.scan_id,
        "stats": {
            "requests": len(network_events["requests"]),
            "responses": len(network_events["responses"]),
            "failed_requests": len(network_events["failed_requests"]),
            "blocked_requests": len(network_events["blocked_requests"]),
            "domains": len(domains),
            "ips": len(ips),
            "redirects": len(redirects),
            "links": result.links_count or 0,
            "console_messages": len(console_messages),
            "page_errors": len(page_errors),
            "downloads": len(downloads),
        },
        "resource_types": [
            {"type": resource_type, "count": count}
            for resource_type, count in resource_types.most_common()
        ],
        "status_codes": [{"status": status, "count": count} for status, count in status_codes.most_common()],
        "domains": domains,
        "ips": ips,
        "redirects": redirects,
        "console": {
            "levels": [
                {"level": level, "count": count}
                for level, count in Counter(message["type"] for message in console_messages).most_common()
            ],
            "messages": console_messages,
            "page_errors": page_errors,
        },
        "primary_response": primary_response,
    }


def resolve_network(url: str, requested: NetworkMode) -> NetworkMode:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetValidationError("URL must be an absolute http or https URL")

    is_onion = parsed.hostname.lower().endswith(".onion")
    selected = NetworkMode.TOR if requested is NetworkMode.AUTO and is_onion else requested
    if requested is NetworkMode.AUTO and not is_onion:
        selected = NetworkMode.DIRECT
    if is_onion and selected is not NetworkMode.TOR:
        raise TargetValidationError(".onion targets require Tor mode")
    return selected


def reject_non_public_direct_target(url: str) -> None:
    """Prevent direct-mode scans from reaching local or private network addresses."""
    host = urlsplit(url).hostname
    if host is None:
        raise TargetValidationError("URL host is required")
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise TargetValidationError("localhost is not a valid Direct target")

    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, None)}
    except socket.gaierror as error:
        raise TargetValidationError("target hostname could not be resolved") from error

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise TargetValidationError("Direct targets must resolve only to globally routable IP addresses")


async def prepare_page_for_capture(page: Any) -> None:
    """Give normal and viewport-triggered page resources a bounded chance to load."""
    try:
        await page.wait_for_load_state("load", timeout=3_000)
    except PlaywrightTimeoutError:
        # Pages with long-lived requests should still produce a Quick Scan result.
        pass

    try:
        await asyncio.wait_for(
            page.evaluate(
                """async () => {
                    if (document.fonts?.ready) {
                        await document.fonts.ready;
                    }
                }"""
            ),
            timeout=3,
        )
    except (asyncio.TimeoutError, PlaywrightTimeoutError):
        pass

    await page.wait_for_timeout(POST_LOAD_SETTLE_MS)
    await page.evaluate(
        """async ({ pauseMs, maxSteps }) => {
            const pause = () => new Promise((resolve) => setTimeout(resolve, pauseMs));
            const root = document.documentElement;
            const step = Math.max(window.innerHeight, 640);
            let stableBottomChecks = 0;
            let lastHeight = 0;
            let steps = 0;

            for (; steps < maxSteps; steps += 1) {
                window.scrollBy(0, step);
                await pause();

                const height = Math.max(root.scrollHeight, document.body?.scrollHeight || 0);
                const atBottom = window.scrollY + window.innerHeight >= height - 2;
                if (atBottom && height === lastHeight) {
                    stableBottomChecks += 1;
                    if (stableBottomChecks >= 2) break;
                } else {
                    stableBottomChecks = 0;
                }
                lastHeight = height;
            }

            window.scrollTo(0, 0);
            await pause();
            return { steps, finalHeight: Math.max(root.scrollHeight, document.body?.scrollHeight || 0) };
        }""",
        {"pauseMs": LAZY_SCROLL_PAUSE_MS, "maxSteps": MAX_LAZY_SCROLL_STEPS},
    )


async def run_quick_scan(request: QuickScanRequest) -> QuickScanResult:
    network = resolve_network(request.url, request.network)
    if network is NetworkMode.DIRECT:
        reject_non_public_direct_target(request.url)

    scan_id = uuid.uuid4().hex
    output_dir = artifact_root() / scan_id
    output_dir.mkdir(parents=True, exist_ok=False)
    result = QuickScanResult(scan_id=scan_id, network=network, reachable=False, final_url=request.url)
    network_events: dict[str, list[dict[str, Any]]] = {
        "requests": [],
        "responses": [],
        "failed_requests": [],
        "blocked_requests": [],
    }
    redirects: list[dict[str, Any]] = []
    console_messages: list[dict[str, Any]] = []
    page_errors: list[dict[str, str]] = []
    downloads: list[dict[str, Any]] = []
    response_tasks: list[asyncio.Task[None]] = []
    download_tasks: list[asyncio.Task[None]] = []

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={"server": TOR_SOCKS_URL} if network is NetworkMode.TOR else None,
            )
            context = None
            try:
                context = await browser.new_context(accept_downloads=True)
                await context.tracing.start(screenshots=True, snapshots=True, sources=False)
                if network is NetworkMode.DIRECT:
                    async def enforce_public_egress(route: Any) -> None:
                        target_url = route.request.url
                        if urlsplit(target_url).scheme in {"http", "https"}:
                            try:
                                reject_non_public_direct_target(target_url)
                            except TargetValidationError as error:
                                network_events["blocked_requests"].append(
                                    {"url": target_url, "reason": str(error)}
                                )
                                await route.abort("blockedbyclient")
                                return
                        await route.continue_()

                    await context.route("**/*", enforce_public_egress)

                page = await context.new_page()

                def record_request(playwright_request: Any) -> None:
                    network_events["requests"].append(
                        {
                            "url": playwright_request.url,
                            "method": playwright_request.method,
                            "resource_type": playwright_request.resource_type,
                            "headers": redacted_headers(playwright_request.headers),
                        }
                    )
                    if playwright_request.redirected_from:
                        redirects.append(
                            {
                                "from_url": playwright_request.redirected_from.url,
                                "to_url": playwright_request.url,
                                "kind": "http",
                            }
                        )

                async def record_response(playwright_response: Any) -> None:
                    try:
                        server_address = await playwright_response.server_addr()
                    except Exception:
                        server_address = None
                    try:
                        headers = await playwright_response.all_headers()
                    except Exception:
                        headers = playwright_response.headers
                    network_events["responses"].append(
                        {
                            "url": playwright_response.url,
                            "status": playwright_response.status,
                            "status_text": playwright_response.status_text,
                            "resource_type": playwright_response.request.resource_type,
                            "headers": redacted_headers(headers),
                            "server_address": server_address,
                            "timing": playwright_response.request.timing,
                        }
                    )

                def schedule_response(playwright_response: Any) -> None:
                    response_tasks.append(asyncio.create_task(record_response(playwright_response)))

                def record_failed_request(playwright_request: Any) -> None:
                    network_events["failed_requests"].append(
                        {
                            "url": playwright_request.url,
                            "method": playwright_request.method,
                            "resource_type": playwright_request.resource_type,
                            "failure": playwright_request.failure,
                        }
                    )

                def record_console(message: Any) -> None:
                    console_messages.append(
                        {"type": message.type, "text": message.text, "location": message.location}
                    )

                def record_page_error(error: Any) -> None:
                    page_errors.append({"message": str(error)})

                async def persist_download(download: Any) -> None:
                    download_dir = output_dir / "downloads"
                    download_dir.mkdir(exist_ok=True)
                    safe_name = Path(download.suggested_filename).name or "download"
                    destination = download_dir / f"{len(downloads):03d}_{safe_name}"
                    try:
                        await download.save_as(destination)
                        payload = destination.read_bytes()
                        downloads.append(
                            {
                                "url": download.url,
                                "suggested_filename": download.suggested_filename,
                                "path": str(destination),
                                "size_bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "error": None,
                            }
                        )
                    except Exception as error:
                        downloads.append(
                            {
                                "url": download.url,
                                "suggested_filename": download.suggested_filename,
                                "error": f"{type(error).__name__}: {error}",
                            }
                        )

                def schedule_download(download: Any) -> None:
                    download_tasks.append(asyncio.create_task(persist_download(download)))

                page.on("request", record_request)
                page.on("response", schedule_response)
                page.on("requestfailed", record_failed_request)
                page.on("console", record_console)
                page.on("pageerror", record_page_error)
                page.on("download", schedule_download)

                response = await page.goto(request.url, wait_until="domcontentloaded", timeout=SCAN_TIMEOUT_MS)
                await prepare_page_for_capture(page)
                html = await page.content()
                screenshot = output_dir / "screenshot.png"
                page_html = output_dir / "page.html"
                await page.screenshot(path=str(screenshot), full_page=True)
                page_html.write_text(html, encoding="utf-8")

                result.reachable = True
                result.status = response.status if response else None
                result.title = await page.title()
                result.final_url = page.url
                result.screenshot_path = str(screenshot)
                result.html_path = str(page_html)
                result.html_sha256 = hashlib.sha256(html.encode("utf-8")).hexdigest()
                result.links_count = await page.locator("a[href]").count()
            finally:
                if response_tasks:
                    await asyncio.gather(*response_tasks, return_exceptions=True)
                if download_tasks:
                    await asyncio.gather(*download_tasks, return_exceptions=True)
                result.requests_count = len(network_events["requests"])
                result.failed_requests_count = len(network_events["failed_requests"])
                result.redirects_count = len(redirects)
                result.console_messages_count = len(console_messages)
                result.page_errors_count = len(page_errors)
                result.downloads_count = len(downloads)
                if context is not None:
                    try:
                        await context.tracing.stop(path=str(output_dir / "trace.zip"))
                    finally:
                        await context.close()
                await browser.close()
    except Exception as error:
        result.error = f"{type(error).__name__}: {error}"

    write_json(output_dir / "network.json", network_events)
    write_json(output_dir / "redirects.json", {"redirects": redirects})
    write_json(output_dir / "console.json", {"messages": console_messages, "page_errors": page_errors})
    write_json(output_dir / "downloads.json", {"downloads": downloads})
    write_json(
        output_dir / "summary.json",
        build_scan_summary(result, network_events, redirects, console_messages, page_errors, downloads),
    )
    metadata = output_dir / "metadata.json"
    write_json(
        metadata,
        {"created_at": datetime.now(UTC).isoformat(), **result.model_dump(mode="json")},
    )
    return result
