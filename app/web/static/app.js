const form = document.querySelector("#scan-form");
const button = document.querySelector("#scan-button");
const progressPanel = document.querySelector("#progress-panel");
const errorPanel = document.querySelector("#error-panel");
const resultPanel = document.querySelector("#result-panel");
const apiStatus = document.querySelector("#api-status");
const liveScanButton = document.querySelector("#live-scan-button");
const liveSessionPanel = document.querySelector("#live-session-panel");
const stopLiveScanButton = document.querySelector("#stop-live-scan-button");
let activeLiveScanId = null;
let liveObservationTimer = null;

function show(element, visible) {
  element.classList.toggle("hidden", !visible);
}

function displayValue(value) {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

async function readError(response) {
  try {
    const body = await response.json();
    return body.detail || JSON.stringify(body);
  } catch {
    return `${response.status} ${response.statusText}`;
  }
}

function addMetadata(label, value) {
  const metadata = document.querySelector("#metadata");
  const term = document.createElement("dt");
  const definition = document.createElement("dd");
  term.textContent = label;
  definition.textContent = displayValue(value);
  metadata.append(term, definition);
}

function setText(selector, value) {
  document.querySelector(selector).textContent = displayValue(value);
}

function populateRows(selector, rows, values, emptyMessage) {
  const body = document.querySelector(selector);
  body.replaceChildren();
  if (values.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = rows;
    cell.className = "empty-row";
    cell.textContent = emptyMessage;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const valuesForRow of values) {
    const row = document.createElement("tr");
    for (const value of valuesForRow) {
      const cell = document.createElement("td");
      cell.textContent = displayValue(value);
      row.append(cell);
    }
    body.append(row);
  }
}

function renderSummary(summary) {
  const stats = summary.stats;
  const values = {
    requests: stats.requests,
    domains: stats.domains,
    ips: stats.ips,
    redirects: stats.redirects,
    links: stats.links,
    failed: stats.failed_requests,
    console: stats.console_messages,
    errors: stats.page_errors,
    downloads: stats.downloads,
  };
  for (const [name, value] of Object.entries(values)) {
    document.querySelector(`[data-stat="${name}"]`).textContent = displayValue(value);
  }

  setText("#domain-count", `${stats.domains} domains`);
  setText("#ip-count", `${stats.ips} IPs`);
  setText("#redirect-count", `${stats.redirects} redirects`);
  setText("#console-count", `${stats.console_messages} messages`);
  setText("#page-error-count", `${stats.page_errors} errors`);

  populateRows("#domain-table", 4, summary.domains.map((domain) => [
    domain.domain,
    domain.requests,
    domain.ips.join(", ") || "—",
    Object.entries(domain.statuses).map(([status, count]) => `${status} ×${count}`).join(", ") || "—",
  ]), "No network domains captured.");
  populateRows("#ip-table", 3, summary.ips.map((ip) => [
    ip.ip,
    ip.responses,
    ip.domains.join(", "),
  ]), "No server IP addresses captured.");
  populateRows("#redirect-table", 3, summary.redirects.map((redirect) => [
    redirect.kind,
    redirect.from_url,
    redirect.to_url,
  ]), "No redirects recorded.");
  populateRows("#console-table", 2, summary.console.messages.map((message) => [
    message.type,
    message.text,
  ]), "No console messages recorded.");
  populateRows("#page-error-table", 1, summary.console.page_errors.map((error) => [error.message]), "No page errors recorded.");

  const breakdown = document.querySelector("#network-breakdown");
  breakdown.replaceChildren();
  const overviewItems = [
    ...summary.resource_types.map((entry) => [`${entry.type} requests`, entry.count]),
    ...summary.status_codes.map((entry) => [`HTTP ${entry.status}`, entry.count]),
  ];
  for (const item of overviewItems) {
    const row = document.createElement("div");
    const label = document.createElement("span");
    const count = document.createElement("strong");
    label.textContent = item[0];
    count.textContent = item[1];
    row.append(label, count);
    breakdown.append(row);
  }
}

async function renderResult(scan) {
  document.querySelector("#result-heading").textContent = scan.title || "Untitled page";
  const badge = document.querySelector("#result-status");
  badge.textContent = scan.reachable ? `${scan.status ?? "?"} · ${scan.network}` : "Unreachable";
  badge.classList.toggle("failure", !scan.reachable);

  const metadata = document.querySelector("#metadata");
  metadata.replaceChildren();
  addMetadata("Scan ID", scan.scan_id);
  addMetadata("Final URL", scan.final_url);
  addMetadata("HTML SHA-256", scan.html_sha256);
  addMetadata("Error", scan.error);

  const initialStats = {
    requests: scan.requests_count,
    redirects: scan.redirects_count,
    links: scan.links_count,
    console: scan.console_messages_count,
    errors: scan.page_errors_count,
    downloads: scan.downloads_count,
  };
  for (const [name, value] of Object.entries(initialStats)) {
    document.querySelector(`[data-stat="${name}"]`).textContent = displayValue(value);
  }

  const screenshot = document.querySelector("#screenshot");
  const screenshotUrl = `/scans/${encodeURIComponent(scan.scan_id)}/screenshot`;
  screenshot.src = screenshotUrl;
  document.querySelector("#screenshot-expanded").src = screenshotUrl;
  screenshot.closest(".screenshot-viewport").classList.toggle("hidden", !scan.reachable);
  document.querySelector("#screenshot-expanded").closest(".screenshot-viewport").classList.toggle("hidden", !scan.reachable);

  document.querySelector("#html-link").href = `/scans/${encodeURIComponent(scan.scan_id)}/html`;
  const artifactList = document.querySelector("#artifact-list");
  artifactList.replaceChildren();
  const artifactsResponse = await fetch(`/scans/${encodeURIComponent(scan.scan_id)}/artifacts`);
  if (artifactsResponse.ok) {
    const artifacts = await artifactsResponse.json();
    for (const artifact of artifacts.artifacts) {
      const item = document.createElement("li");
      if (artifact.name.endsWith(".json")) {
        const link = document.createElement("a");
        link.href = `/scans/${encodeURIComponent(scan.scan_id)}/artifacts/${artifact.name}`;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = artifact.name;
        item.append(link, ` · ${artifact.size_bytes.toLocaleString()} bytes`);
      } else {
        item.textContent = `${artifact.name} · ${artifact.size_bytes.toLocaleString()} bytes`;
      }
      artifactList.append(item);
    }
  }

  const summaryResponse = await fetch(`/scans/${encodeURIComponent(scan.scan_id)}/summary`);
  if (summaryResponse.ok) {
    renderSummary(await summaryResponse.json());
  }
}

async function checkHealth() {
  try {
    const response = await fetch("/health");
    if (!response.ok) throw new Error();
    apiStatus.textContent = "API online";
    apiStatus.classList.add("online");
  } catch {
    apiStatus.textContent = "API unavailable";
  }
}

function liveViewerUrl() {
  const viewerHost = window.location.hostname.replace(
    /-8000(?=\.app\.github\.dev$)/,
    "-6080",
  );
  if (viewerHost !== window.location.hostname) {
    return `${window.location.protocol}//${viewerHost}/vnc.html?autoconnect=true&resize=scale&path=websockify`;
  }
  return `${window.location.protocol}//${window.location.hostname}:6080/vnc.html?autoconnect=true&resize=scale&path=websockify`;
}

function renderLiveSession(session) {
  activeLiveScanId = session.scan_id;
  setText("#live-session-network", session.network);
  const link = document.querySelector("#live-browser-link");
  link.href = liveViewerUrl();
  link.textContent = "Open remote browser ↗";
  document.querySelector("#live-browser-frame").src = liveViewerUrl();
}

function renderLiveObservations(observations) {
  const minutes = Math.floor(observations.elapsed_seconds / 60);
  const seconds = observations.elapsed_seconds % 60;
  setText("#live-elapsed", `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`);
  const stats = observations.stats;
  setText("#live-requests", stats.requests);
  setText("#live-domains", stats.domains);
  setText("#live-redirects", stats.redirects);
  setText("#live-console", stats.console);
  setText("#live-errors", stats.page_errors);
  setText("#live-downloads", stats.downloads);

  const feed = document.querySelector("#live-request-feed");
  feed.replaceChildren();
  if (observations.recent_requests.length === 0) {
    const item = document.createElement("li");
    item.textContent = "Waiting for browser traffic…";
    feed.append(item);
    return;
  }
  for (const request of observations.recent_requests) {
    const item = document.createElement("li");
    const label = document.createElement("strong");
    label.textContent = `${request.method} · ${request.resource_type}`;
    const url = document.createElement("span");
    url.textContent = request.url;
    item.append(label, url);
    feed.append(item);
  }
}

async function updateLiveObservations() {
  if (!activeLiveScanId) return;
  try {
    const response = await fetch(`/scans/live/${encodeURIComponent(activeLiveScanId)}/observations`);
    if (!response.ok) return;
    renderLiveObservations(await response.json());
  } catch {
    // A transient poll failure should not interrupt the manual browser session.
  }
}

function startLiveObservationPolling() {
  if (liveObservationTimer !== null) clearInterval(liveObservationTimer);
  updateLiveObservations();
  liveObservationTimer = setInterval(updateLiveObservations, 1500);
}

function stopLiveObservationPolling() {
  if (liveObservationTimer !== null) clearInterval(liveObservationTimer);
  liveObservationTimer = null;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const payload = { url: data.get("url"), network: data.get("network") };

  show(errorPanel, false);
  show(liveSessionPanel, false);
  show(resultPanel, false);
  show(progressPanel, true);
  button.disabled = true;
  liveScanButton.disabled = true;

  try {
    const response = await fetch("/scans/quick", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await readError(response));
    const scan = await response.json();
    await renderResult(scan);
    show(resultPanel, true);
    document.body.classList.add("showing-result");
  } catch (error) {
    document.querySelector("#error-message").textContent = error.message;
    show(errorPanel, true);
  } finally {
    show(progressPanel, false);
    button.disabled = false;
    liveScanButton.disabled = false;
  }
});

liveScanButton.addEventListener("click", async () => {
  if (!form.reportValidity()) return;
  const data = new FormData(form);
  const payload = { url: data.get("url"), network: data.get("network") };

  show(errorPanel, false);
  show(resultPanel, false);
  show(progressPanel, true);
  document.querySelector("#progress-message").textContent = "Starting visible remote browser…";
  button.disabled = true;
  liveScanButton.disabled = true;

  try {
    const response = await fetch("/scans/live", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await readError(response));
    const session = await response.json();
    if (session.status !== "active") throw new Error(session.error || "Live Scan could not start");
    renderLiveSession(session);
    show(liveSessionPanel, true);
    document.body.classList.add("showing-live");
    startLiveObservationPolling();
  } catch (error) {
    document.querySelector("#error-message").textContent = error.message;
    show(errorPanel, true);
  } finally {
    show(progressPanel, false);
    document.querySelector("#progress-message").textContent = "Creating remote browser session…";
    button.disabled = false;
    liveScanButton.disabled = false;
  }
});

stopLiveScanButton.addEventListener("click", async () => {
  if (!activeLiveScanId) return;
  stopLiveScanButton.disabled = true;
  stopLiveScanButton.textContent = "Capturing session…";
  try {
    const response = await fetch(`/scans/live/${encodeURIComponent(activeLiveScanId)}/stop`, { method: "POST" });
    if (!response.ok) throw new Error(await readError(response));
    const scan = await response.json();
    await renderResult(scan);
    show(liveSessionPanel, false);
    show(resultPanel, true);
    stopLiveObservationPolling();
    document.body.classList.remove("showing-live");
    document.body.classList.add("showing-result");
    activeLiveScanId = null;
  } catch (error) {
    document.querySelector("#error-message").textContent = error.message;
    show(errorPanel, true);
  } finally {
    stopLiveScanButton.disabled = false;
    stopLiveScanButton.textContent = "Stop & capture";
  }
});

checkHealth();

document.querySelector("#new-scan-button").addEventListener("click", () => {
  document.body.classList.remove("showing-result");
  document.body.classList.remove("showing-live");
  stopLiveObservationPolling();
  show(resultPanel, false);
  show(liveSessionPanel, false);
  document.querySelector("#target-url").focus();
});

for (const tab of document.querySelectorAll("[data-tab]")) {
  tab.addEventListener("click", () => {
    const selected = tab.dataset.tab;
    for (const candidate of document.querySelectorAll(".result-tab")) {
      candidate.classList.toggle("active", candidate.dataset.tab === selected);
    }
    for (const panel of document.querySelectorAll(".tab-panel")) {
      panel.classList.toggle("active", panel.dataset.panel === selected);
    }
  });
}
