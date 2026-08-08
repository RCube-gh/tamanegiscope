#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

if ! pgrep -x tor >/dev/null; then
  nohup tor >/tmp/tamanegiscope-tor.log 2>&1 &
fi

if ! pgrep -f '[u]vicorn app\.main:app' >/dev/null; then
  nohup python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    >/tmp/tamanegiscope-api.log 2>&1 &
fi
