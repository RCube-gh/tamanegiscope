from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.models import QuickScanRequest, QuickScanResult, ScanArtifacts
from app.scanner import (
    ScanNotFoundError,
    TargetValidationError,
    list_artifacts,
    load_scan_result,
    run_quick_scan,
    scan_artifact,
)

app = FastAPI(title="TamanegiScope", version="0.1.0")
WEB_ROOT = Path(__file__).resolve().parent / "web"
app.mount("/static", StaticFiles(directory=WEB_ROOT / "static"), name="static")


@app.get("/", include_in_schema=False)
async def web_ui() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans/quick", response_model=QuickScanResult)
async def quick_scan(request: QuickScanRequest) -> QuickScanResult:
    try:
        return await run_quick_scan(request)
    except TargetValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/scans/{scan_id}", response_model=QuickScanResult)
async def get_scan(scan_id: str) -> QuickScanResult:
    try:
        return load_scan_result(scan_id)
    except ScanNotFoundError as error:
        raise HTTPException(status_code=404, detail="scan not found") from error


@app.get("/scans/{scan_id}/artifacts", response_model=ScanArtifacts)
async def get_scan_artifacts(scan_id: str) -> ScanArtifacts:
    try:
        return list_artifacts(scan_id)
    except ScanNotFoundError as error:
        raise HTTPException(status_code=404, detail="scan not found") from error


@app.get("/scans/{scan_id}/screenshot")
async def get_screenshot(scan_id: str) -> FileResponse:
    try:
        screenshot = scan_artifact(scan_id, "screenshot.png")
    except ScanNotFoundError as error:
        raise HTTPException(status_code=404, detail="screenshot not found") from error
    return FileResponse(screenshot, media_type="image/png")


@app.get("/scans/{scan_id}/html", response_class=PlainTextResponse)
async def get_html(scan_id: str) -> PlainTextResponse:
    try:
        page_html = scan_artifact(scan_id, "page.html")
    except ScanNotFoundError as error:
        raise HTTPException(status_code=404, detail="HTML artifact not found") from error
    return PlainTextResponse(page_html.read_text(encoding="utf-8"), media_type="text/plain")


@app.get("/scans/{scan_id}/artifacts/{artifact_name:path}", response_class=PlainTextResponse)
async def get_text_artifact(scan_id: str, artifact_name: str) -> PlainTextResponse:
    if Path(artifact_name).suffix != ".json":
        raise HTTPException(status_code=404, detail="text artifact not found")
    try:
        artifact = scan_artifact(scan_id, artifact_name)
    except ScanNotFoundError as error:
        raise HTTPException(status_code=404, detail="artifact not found") from error
    return PlainTextResponse(artifact.read_text(encoding="utf-8"), media_type="application/json")
