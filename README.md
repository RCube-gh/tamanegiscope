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
```

`POST /scans/quick` accepts a URL and `auto`, `direct`, or `tor` network selection. Auto selects Tor for `.onion` hosts and Direct for other HTTP(S) hosts. Direct targets are rejected when they resolve to non-public IP addresses.

## Running in the runner

After the Codespace has built its dev container and installed its dependencies:

```bash
tor &
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open the forwarded port 8000 from GitHub Codespaces and call `/health`. The `/docs` page provides the initial API interface.
