#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."
export DISPLAY=:99

if ! pgrep -x tor >/dev/null; then
  nohup tor >/tmp/tamanegiscope-tor.log 2>&1 &
fi

if ! pgrep -f '[X]vfb :99' >/dev/null; then
  nohup Xvfb :99 -screen 0 1440x900x24 -ac +extension GLX +render -noreset \
    >/tmp/tamanegiscope-xvfb.log 2>&1 &
  sleep 1
fi

if ! pgrep -x fluxbox >/dev/null; then
  nohup fluxbox >/tmp/tamanegiscope-fluxbox.log 2>&1 &
fi

if ! pgrep -x x11vnc >/dev/null; then
  nohup x11vnc -display :99 -forever -shared -rfbport 5900 -nopw \
    >/tmp/tamanegiscope-x11vnc.log 2>&1 &
fi

if ! pgrep -f '[w]ebsockify.*6080' >/dev/null; then
  nohup websockify --web=/usr/share/novnc 6080 localhost:5900 \
    >/tmp/tamanegiscope-novnc.log 2>&1 &
fi

if ! pgrep -f '[u]vicorn app\.main:app' >/dev/null; then
  nohup python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    >/tmp/tamanegiscope-api.log 2>&1 &
fi
