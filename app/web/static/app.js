const form = document.querySelector("#scan-form");
const button = document.querySelector("#scan-button");
const progressPanel = document.querySelector("#progress-panel");
const errorPanel = document.querySelector("#error-panel");
const resultPanel = document.querySelector("#result-panel");
const apiStatus = document.querySelector("#api-status");

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
  addMetadata("Links", scan.links_count);
  addMetadata("Error", scan.error);

  const screenshot = document.querySelector("#screenshot");
  screenshot.src = `/scans/${encodeURIComponent(scan.scan_id)}/screenshot`;
  screenshot.classList.toggle("hidden", !scan.reachable);

  document.querySelector("#html-link").href = `/scans/${encodeURIComponent(scan.scan_id)}/html`;
  const artifactList = document.querySelector("#artifact-list");
  artifactList.replaceChildren();
  const artifactsResponse = await fetch(`/scans/${encodeURIComponent(scan.scan_id)}/artifacts`);
  if (artifactsResponse.ok) {
    const artifacts = await artifactsResponse.json();
    for (const artifact of artifacts.artifacts) {
      const item = document.createElement("li");
      item.textContent = `${artifact.name} · ${artifact.size_bytes.toLocaleString()} bytes`;
      artifactList.append(item);
    }
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const payload = { url: data.get("url"), network: data.get("network") };

  show(errorPanel, false);
  show(resultPanel, false);
  show(progressPanel, true);
  button.disabled = true;

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
  } catch (error) {
    document.querySelector("#error-message").textContent = error.message;
    show(errorPanel, true);
  } finally {
    show(progressPanel, false);
    button.disabled = false;
  }
});

checkHealth();
