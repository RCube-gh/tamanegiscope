# TamanegiScope

Phase 1 PoC for observing web pages from a cloud-hosted runner rather than opening target pages in the user's local browser. It provides both a one-shot Quick Scan and a Live Scan session with a visible, remotely controlled browser.

The cloud runner exists first to protect the user: it keeps the user's identity and local IP address away from the target, and keeps potentially hostile pages, scripts, downloads, and browser exploits away from the user's local device and network. TamanegiScope is an observation environment, not a promise of complete anonymity or containment; treat the runner and its artifacts as potentially exposed after every scan.

## Roles

* The local workspace is where source code is changed.
* GitHub stores the source code used to create or update a runner.
* GitHub Codespaces is the provisional cloud runner: it runs Tor, Chromium, Playwright, the API, and a noVNC viewer for Live Scan.
* Scan artifacts are runtime data. They are created under `TAMANEGI_ARTIFACT_ROOT` or the operating system temporary directory, outside this repository.

The runner does not commit or push scan artifacts to GitHub.

## Phase 1 API

```text
GET  /health
POST /scans/quick
POST /scans/live
GET  /scans/live/{scan_id}
GET  /scans/live/{scan_id}/observations
POST /scans/live/{scan_id}/stop
GET  /scans/{scan_id}
GET  /scans/{scan_id}/summary
GET  /scans/{scan_id}/artifacts
GET  /scans/{scan_id}/screenshot
GET  /scans/{scan_id}/html
GET  /scans/{scan_id}/artifacts/{artifact_name}
```

`POST /scans/quick` accepts a URL and `auto`, `direct`, or `tor` network selection. Auto selects Tor for `.onion` hosts and Direct for other HTTP(S) hosts. Direct targets are rejected when they resolve to non-public IP addresses.

The scan result can be read again using its `scan_id`. `screenshot` is returned as a PNG. The captured `html` endpoint deliberately returns `text/plain`, so the captured page cannot execute in the browser that views the artifact.

Each Quick Scan also records `network.json`, `redirects.json`, `console.json`, `downloads.json`, `storage.json`, `websockets.json`, and a Playwright `trace.zip`. `storage.json` records cookie attributes and web-storage names, sizes, and hashes without retaining their values; `websockets.json` records connection and frame metadata without retaining frame contents. JSON artifacts are available through the artifact endpoint. Request and response `Authorization`, `Cookie`, `Proxy-Authorization`, and `Set-Cookie` header values are redacted before storage.

## Live Scan

`POST /scans/live` starts one interactive Chromium session in the runner and immediately begins navigating to the requested URL. It uses the same network selection and public-IP protection as Quick Scan. Only one Live Scan session can be active at a time.

The web UI embeds the runner's noVNC view on port 6080 and polls the observations endpoint for recent requests, domains, redirects, console messages, page errors, and downloads. In Codespaces, open the forwarded port 8000; the UI derives the corresponding forwarded 6080 viewer URL automatically.

When observation is complete, call `POST /scans/live/{scan_id}/stop`. This captures the current page and finalizes the same artifacts as a Quick Scan, making the resulting `scan_id` available through the standard scan endpoints.

## Web UI

`/` serves the Quick Scan interface. The browser UI calls the same API endpoints listed above; it does not run a separate scan implementation. It displays captured HTML only through the plain-text artifact endpoint.

## Running in the runner

After the Codespace has built its dev container, its startup service installs dependencies and starts Tor, the virtual display, noVNC, and the API. Open forwarded port 8000 and call `/health`; `/docs` provides the API interface. Port 6080 exposes the Live Scan browser viewer.
