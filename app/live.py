from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

from app.config import SCAN_TIMEOUT_MS, TOR_SOCKS_URL, artifact_root
from app.models import LiveScanRequest, LiveScanSession, NetworkMode, QuickScanResult
from app.scanner import (
    TargetValidationError,
    build_scan_summary,
    hostname,
    redacted_headers,
    reject_non_public_direct_target,
    resolve_network,
    write_json,
)


class LiveScanError(RuntimeError):
    pass


class LiveSession:
    def __init__(self, request: LiveScanRequest) -> None:
        self.request = request
        self.scan_id = uuid.uuid4().hex
        self.network = resolve_network(request.url, request.network)
        if self.network is NetworkMode.DIRECT:
            reject_non_public_direct_target(request.url)

        self.output_dir = artifact_root() / self.scan_id
        self.result = QuickScanResult(
            scan_id=self.scan_id,
            scan_type="live",
            network=self.network,
            reachable=False,
            final_url=request.url,
        )
        self.status = "starting"
        self.started_at = time.monotonic()
        self.error: str | None = None
        self.network_events: dict[str, list[dict[str, Any]]] = {
            "requests": [],
            "responses": [],
            "failed_requests": [],
            "blocked_requests": [],
        }
        self.redirects: list[dict[str, Any]] = []
        self.console_messages: list[dict[str, Any]] = []
        self.page_errors: list[dict[str, str]] = []
        self.downloads: list[dict[str, Any]] = []
        self.response_tasks: list[asyncio.Task[None]] = []
        self.download_tasks: list[asyncio.Task[None]] = []
        self.playwright: Any = None
        self.browser: Any = None
        self.context: Any = None
        self.page: Any = None

    def detail(self) -> LiveScanSession:
        return LiveScanSession(
            scan_id=self.scan_id,
            network=self.network,
            requested_url=self.request.url,
            final_url=self.page.url if self.page else self.result.final_url,
            status=self.status,
            error=self.error,
        )

    def observations(self) -> dict[str, Any]:
        domains = {
            target
            for event in self.network_events["requests"]
            if (target := hostname(event["url"])) is not None
        }
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "elapsed_seconds": int(time.monotonic() - self.started_at),
            "stats": {
                "requests": len(self.network_events["requests"]),
                "responses": len(self.network_events["responses"]),
                "domains": len(domains),
                "redirects": len(self.redirects),
                "console": len(self.console_messages),
                "page_errors": len(self.page_errors),
                "downloads": len(self.downloads),
            },
            "recent_requests": list(reversed(self.network_events["requests"][-8:])),
            "recent_console": list(reversed(self.console_messages[-5:])),
        }

    async def start(self) -> LiveScanSession:
        self.output_dir.mkdir(parents=True, exist_ok=False)
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=False,
                proxy={"server": TOR_SOCKS_URL} if self.network is NetworkMode.TOR else None,
                args=["--window-size=1440,900"],
            )
            self.context = await self.browser.new_context(
                accept_downloads=True,
                viewport={"width": 1440, "height": 900},
            )
            await self.context.tracing.start(screenshots=True, snapshots=True, sources=False)
            if self.network is NetworkMode.DIRECT:
                await self.context.route("**/*", self._enforce_public_egress)
            self.page = await self.context.new_page()
            self._install_observers()
            response = await self.page.goto(
                self.request.url,
                wait_until="domcontentloaded",
                timeout=SCAN_TIMEOUT_MS,
            )
            self.result.reachable = True
            self.result.status = response.status if response else None
            self.result.final_url = self.page.url
            self.status = "active"
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"
            self.status = "failed"
            await self._close_browser()
        return self.detail()

    async def _enforce_public_egress(self, route: Any) -> None:
        target_url = route.request.url
        if urlsplit(target_url).scheme in {"http", "https"}:
            try:
                reject_non_public_direct_target(target_url)
            except TargetValidationError as error:
                self.network_events["blocked_requests"].append({"url": target_url, "reason": str(error)})
                await route.abort("blockedbyclient")
                return
        await route.continue_()

    def _install_observers(self) -> None:
        def record_request(playwright_request: Any) -> None:
            self.network_events["requests"].append(
                {
                    "url": playwright_request.url,
                    "method": playwright_request.method,
                    "resource_type": playwright_request.resource_type,
                    "headers": redacted_headers(playwright_request.headers),
                }
            )
            if playwright_request.redirected_from:
                self.redirects.append(
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
            self.network_events["responses"].append(
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
            if playwright_response.request.resource_type == "document":
                self.result.status = playwright_response.status

        def schedule_response(playwright_response: Any) -> None:
            self.response_tasks.append(asyncio.create_task(record_response(playwright_response)))

        def record_failed_request(playwright_request: Any) -> None:
            self.network_events["failed_requests"].append(
                {
                    "url": playwright_request.url,
                    "method": playwright_request.method,
                    "resource_type": playwright_request.resource_type,
                    "failure": playwright_request.failure,
                }
            )

        def record_console(message: Any) -> None:
            self.console_messages.append(
                {"type": message.type, "text": message.text, "location": message.location}
            )

        def record_page_error(error: Any) -> None:
            self.page_errors.append({"message": str(error)})

        async def persist_download(download: Any) -> None:
            download_dir = self.output_dir / "downloads"
            download_dir.mkdir(exist_ok=True)
            safe_name = Path(download.suggested_filename).name or "download"
            destination = download_dir / f"{len(self.downloads):03d}_{safe_name}"
            try:
                await download.save_as(destination)
                payload = destination.read_bytes()
                self.downloads.append(
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
                self.downloads.append(
                    {
                        "url": download.url,
                        "suggested_filename": download.suggested_filename,
                        "error": f"{type(error).__name__}: {error}",
                    }
                )

        def schedule_download(download: Any) -> None:
            self.download_tasks.append(asyncio.create_task(persist_download(download)))

        self.page.on("request", record_request)
        self.page.on("response", schedule_response)
        self.page.on("requestfailed", record_failed_request)
        self.page.on("console", record_console)
        self.page.on("pageerror", record_page_error)
        self.page.on("download", schedule_download)

    async def stop(self) -> QuickScanResult:
        if self.status == "stopped":
            return self.result
        if self.page is not None and self.status == "active":
            try:
                html = await self.page.content()
                screenshot = self.output_dir / "screenshot.png"
                page_html = self.output_dir / "page.html"
                await self.page.screenshot(path=str(screenshot), full_page=True)
                page_html.write_text(html, encoding="utf-8")
                self.result.title = await self.page.title()
                self.result.final_url = self.page.url
                self.result.screenshot_path = str(screenshot)
                self.result.html_path = str(page_html)
                self.result.html_sha256 = hashlib.sha256(html.encode("utf-8")).hexdigest()
                self.result.links_count = await self.page.locator("a[href]").count()
            except Exception as error:
                self.error = f"{type(error).__name__}: {error}"
                self.result.error = self.error

        await self._finalize_artifacts()
        await self._close_browser()
        self.status = "stopped"
        return self.result

    async def _finalize_artifacts(self) -> None:
        if self.response_tasks:
            await asyncio.gather(*self.response_tasks, return_exceptions=True)
        if self.download_tasks:
            await asyncio.gather(*self.download_tasks, return_exceptions=True)
        self.result.requests_count = len(self.network_events["requests"])
        self.result.failed_requests_count = len(self.network_events["failed_requests"])
        self.result.redirects_count = len(self.redirects)
        self.result.console_messages_count = len(self.console_messages)
        self.result.page_errors_count = len(self.page_errors)
        self.result.downloads_count = len(self.downloads)
        write_json(self.output_dir / "network.json", self.network_events)
        write_json(self.output_dir / "redirects.json", {"redirects": self.redirects})
        write_json(
            self.output_dir / "console.json",
            {"messages": self.console_messages, "page_errors": self.page_errors},
        )
        write_json(self.output_dir / "downloads.json", {"downloads": self.downloads})
        write_json(
            self.output_dir / "summary.json",
            build_scan_summary(
                self.result,
                self.network_events,
                self.redirects,
                self.console_messages,
                self.page_errors,
                self.downloads,
            ),
        )
        write_json(
            self.output_dir / "metadata.json",
            {"created_at": datetime.now(UTC).isoformat(), **self.result.model_dump(mode="json")},
        )

    async def _close_browser(self) -> None:
        if self.context is not None:
            try:
                await self.context.tracing.stop(path=str(self.output_dir / "trace.zip"))
            except Exception:
                pass
            await self.context.close()
            self.context = None
        if self.browser is not None:
            await self.browser.close()
            self.browser = None
        if self.playwright is not None:
            await self.playwright.stop()
            self.playwright = None


class LiveSessionManager:
    def __init__(self) -> None:
        self.session: LiveSession | None = None
        self.lock = asyncio.Lock()

    async def start(self, request: LiveScanRequest) -> LiveScanSession:
        async with self.lock:
            if self.session is not None and self.session.status == "active":
                raise LiveScanError("a Live Scan session is already active")
            session = LiveSession(request)
            self.session = session
            return await session.start()

    async def detail(self, scan_id: str) -> LiveScanSession:
        if self.session is None or self.session.scan_id != scan_id:
            raise LiveScanError("live scan session not found")
        return self.session.detail()

    async def stop(self, scan_id: str) -> QuickScanResult:
        async with self.lock:
            if self.session is None or self.session.scan_id != scan_id:
                raise LiveScanError("live scan session not found")
            return await self.session.stop()

    async def observations(self, scan_id: str) -> dict[str, Any]:
        if self.session is None or self.session.scan_id != scan_id:
            raise LiveScanError("live scan session not found")
        return self.session.observations()

    async def shutdown(self) -> None:
        async with self.lock:
            if self.session is not None and self.session.status == "active":
                await self.session.stop()
