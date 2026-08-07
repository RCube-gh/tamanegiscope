from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

from app.config import SCAN_TIMEOUT_MS, TOR_SOCKS_URL, artifact_root
from app.models import NetworkMode, QuickScanRequest, QuickScanResult


class TargetValidationError(ValueError):
    pass


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


async def run_quick_scan(request: QuickScanRequest) -> QuickScanResult:
    network = resolve_network(request.url, request.network)
    if network is NetworkMode.DIRECT:
        reject_non_public_direct_target(request.url)

    scan_id = uuid.uuid4().hex
    output_dir = artifact_root() / scan_id
    output_dir.mkdir(parents=True, exist_ok=False)
    result = QuickScanResult(scan_id=scan_id, network=network, reachable=False, final_url=request.url)

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={"server": TOR_SOCKS_URL} if network is NetworkMode.TOR else None,
            )
            try:
                context = await browser.new_context(accept_downloads=False)
                page = await context.new_page()
                response = await page.goto(request.url, wait_until="domcontentloaded", timeout=SCAN_TIMEOUT_MS)
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
                await context.close()
            finally:
                await browser.close()
    except Exception as error:
        result.error = f"{type(error).__name__}: {error}"

    metadata = output_dir / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(),
                **result.model_dump(mode="json"),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return result
