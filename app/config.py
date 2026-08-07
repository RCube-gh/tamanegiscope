from __future__ import annotations

import os
import tempfile
from pathlib import Path


def artifact_root() -> Path:
    """Return a runtime-only artifact directory outside the checked-out source tree."""
    configured = os.getenv("TAMANEGI_ARTIFACT_ROOT")
    root = Path(configured) if configured else Path(tempfile.gettempdir()) / "tamanegiscope-artifacts"
    root.mkdir(parents=True, exist_ok=True)
    return root


SCAN_TIMEOUT_MS = int(os.getenv("TAMANEGI_SCAN_TIMEOUT_MS", "30000"))
TOR_SOCKS_URL = os.getenv("TAMANEGI_TOR_SOCKS_URL", "socks5://127.0.0.1:9050")
