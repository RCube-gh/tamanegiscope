# TamanegiScope

Phase 1 PoC for observing web pages from a cloud-hosted runner rather than opening target pages in the user's local browser.

## Roles

* The local workspace is where source code is changed.
* GitHub stores the source code used to create or update a runner.
* GitHub Codespaces is the provisional cloud runner: it runs Tor, Chromium, Playwright, and the API.
* Scan artifacts are runtime data. They are created under `TAMANEGI_ARTIFACT_ROOT` or the operating system temporary directory, outside this repository.

The runner does not commit or push scan artifacts to GitHub.

## Phase 1 API

```text
GET  /health
POST /scans/quick
GET  /scans/{scan_id}
GET  /scans/{scan_id}/summary
GET  /scans/{scan_id}/artifacts
GET  /scans/{scan_id}/screenshot
GET  /scans/{scan_id}/html
GET  /scans/{scan_id}/artifacts/{artifact_name}
```

`POST /scans/quick` accepts a URL and `auto`, `direct`, or `tor` network selection. Auto selects Tor for `.onion` hosts and Direct for other HTTP(S) hosts. Direct targets are rejected when they resolve to non-public IP addresses.

The scan result can be read again using its `scan_id`. `screenshot` is returned as a PNG. The captured `html` endpoint deliberately returns `text/plain`, so the captured page cannot execute in the browser that views the artifact.

Each Quick Scan also records `network.json`, `redirects.json`, `console.json`, `downloads.json`, and a Playwright `trace.zip`. JSON artifacts are available through the artifact endpoint. Request and response `Authorization`, `Cookie`, `Proxy-Authorization`, and `Set-Cookie` header values are redacted before storage.

## Web UI

`/` serves the Quick Scan interface. The browser UI calls the same API endpoints listed above; it does not run a separate scan implementation. It displays captured HTML only through the plain-text artifact endpoint.

## Running in the runner

After the Codespace has built its dev container and installed its dependencies:

```bash
tor &
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open the forwarded port 8000 from GitHub Codespaces and call `/health`. The `/docs` page provides the initial API interface.
