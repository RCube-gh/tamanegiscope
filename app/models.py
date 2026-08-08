from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class NetworkMode(StrEnum):
    AUTO = "auto"
    DIRECT = "direct"
    TOR = "tor"


class QuickScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8_192)
    network: NetworkMode = NetworkMode.AUTO


class QuickScanResult(BaseModel):
    scan_id: str
    scan_type: str = "quick"
    network: NetworkMode
    reachable: bool
    status: int | None = None
    title: str | None = None
    final_url: str | None = None
    screenshot_path: str | None = None
    html_path: str | None = None
    html_sha256: str | None = None
    links_count: int | None = None
    requests_count: int | None = None
    failed_requests_count: int | None = None
    redirects_count: int | None = None
    console_messages_count: int | None = None
    page_errors_count: int | None = None
    downloads_count: int | None = None
    error: str | None = None


class ArtifactInfo(BaseModel):
    name: str
    size_bytes: int
    media_type: str | None = None


class ScanArtifacts(BaseModel):
    scan_id: str
    artifacts: list[ArtifactInfo]
