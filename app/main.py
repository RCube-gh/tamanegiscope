from fastapi import FastAPI, HTTPException

from app.models import QuickScanRequest, QuickScanResult
from app.scanner import TargetValidationError, run_quick_scan

app = FastAPI(title="TamanegiScope", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans/quick", response_model=QuickScanResult)
async def quick_scan(request: QuickScanRequest) -> QuickScanResult:
    try:
        return await run_quick_scan(request)
    except TargetValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
