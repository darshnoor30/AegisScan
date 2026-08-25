const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? "—").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

let activeJobId = null;

document.querySelectorAll(".preset").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".preset").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    $("#ports").value = button.dataset.ports;
  });
});

$("#ports").addEventListener("input", () => {
  document.querySelectorAll(".preset").forEach((item) => item.classList.toggle("active", item.dataset.ports === $("#ports").value.trim()));
});

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("#form-error");
  error.hidden = true;
  if (!$("#authorized").checked) {
    error.textContent = "Confirm that you own the system or have explicit permission to scan it.";
    error.hidden = false;
    return;
  }
  setRunning(true);
  showProgress({stage:"queued", percent:0, completed:0, total:0, open:0});
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        targets: $("#targets").value.split(",").map((item) => item.trim()).filter(Boolean),
        ports: $("#ports").value.trim(),
        timeout: Number($("#timeout").value),
        concurrency: Number($("#concurrency").value),
        authorized: true,
        fingerprint: true
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The scan could not be started.");
    activeJobId = data.job_id;
    await pollJob(data.status_url);
  } catch (failure) {
    setFailed(failure.message);
  }
});

function setRunning(running) {
  $("#scan-button").disabled = running;
  $("#run-status").className = `status ${running ? "running" : "idle"}`;
  $("#run-status").innerHTML = `<i></i> ${running ? "Scanning" : "Ready"}`;
}

function showProgress(progress) {
  $("#empty-state").hidden = true;
  $("#score-state").hidden = true;
  $("#progress-state").hidden = false;
  const percent = Number(progress.percent || 0);
  const labels = {queued:"Queued safely", resolving:"Resolving approved scope", scanning:"Testing TCP reachability", analyzing:"Prioritizing exposure", complete:"Assessment complete"};
  $("#progress-number").textContent = `${Math.round(percent)}%`;
  $("#progress-title").textContent = labels[progress.stage] || "Running assessment";
  $("#progress-detail").textContent = progress.total ? `${progress.completed} of ${progress.total} bounded probes completed.` : "Preparing the authorized scan workers…";
  $("#progress-bar").style.width = `${Math.max(1, percent)}%`;
  $("#probes-done").textContent = progress.completed || 0;
  $("#open-live").textContent = progress.open || 0;
}

async function pollJob(url) {
  while (true) {
    const response = await fetch(url, {cache:"no-store"});
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || "Lost contact with scan job.");
    if (job.status === "failed") throw new Error(job.error || "Scan failed.");
    if (job.status === "complete") {
      renderResult(job.result, job.job_id);
      return;
    }
    showProgress(job.progress || {});
    await sleep(550);
  }
}

function setFailed(message) {
  setRunning(false);
  $("#run-status").className = "status failed";
  $("#run-status").innerHTML = "<i></i> Blocked";
  $("#progress-state").hidden = true;
  $("#score-state").hidden = true;
  $("#empty-state").hidden = false;
  $("#form-error").textContent = message;
  $("#form-error").hidden = false;
}

function renderResult(result, reportId) {
  setRunning(false);
  $("#run-status").className = "status idle";
  $("#run-status").innerHTML = "<i></i> Complete";
  $("#progress-state").hidden = true;
  $("#score-state").hidden = false;
  const summary = result.summary;
  const score = Number(summary.security_score);
  const scoreColor = score >= 80 ? "var(--cyan)" : score >= 60 ? "var(--medium)" : "var(--critical)";
  $("#score-ring").style.background = `conic-gradient(${scoreColor} ${score}%, #1b2638 ${score}% 100%)`;
  $("#score-value").textContent = score;
  $("#grade-pill").textContent = `Grade ${summary.grade}`;
  $("#score-title").textContent = summary.findings ? "Prioritized action required" : "No priority exposure found";
  $("#score-description").textContent = `${summary.open_ports} open service${summary.open_ports === 1 ? "" : "s"} and ${summary.findings} prioritized finding${summary.findings === 1 ? "" : "s"}.`;
  $("#report-link").href = `/reports/${encodeURIComponent(result.scan_id || reportId)}.html`;

  $("#results").hidden = false;
  $("#scan-id").textContent = `SCAN ${result.scan_id}`;
  $("#kpi-assets").textContent = summary.targets;
  $("#kpi-probes").textContent = summary.probes_total.toLocaleString();
  $("#kpi-open").textContent = summary.open_ports;
  $("#kpi-findings").textContent = summary.findings;
  renderServices(result.observations || []);
  renderFindings(result.findings || [], summary.severity_counts || {});
  $("#results").scrollIntoView({behavior:"smooth", block:"start"});
}

function renderServices(items) {
  $("#service-count").textContent = `${items.length} endpoint${items.length === 1 ? "" : "s"}`;
  if (!items.length) {
    $("#services-body").innerHTML = '<tr><td class="table-empty" colspan="5">No open TCP services observed in this scope.</td></tr>';
    return;
  }
  $("#services-body").innerHTML = items.map((item) => {
    const fp = item.fingerprint || {};
    const evidence = fp.product || fp.banner || fp.http?.title || "Reachability confirmed";
    return `<tr><td class="mono">${esc(item.address)}</td><td><span class="service-pill">${esc(item.port)}/tcp</span></td><td>${esc(fp.service || "unknown")}</td><td title="${esc(evidence)}">${esc(String(evidence).slice(0, 42))}</td><td>${esc(item.latency_ms)} ms</td></tr>`;
  }).join("");
}

function renderFindings(items, counts) {
  const order = ["critical", "high", "medium"];
  $("#severity-summary").innerHTML = order.filter((severity) => counts[severity]).map((severity) => `<span title="${severity}">${counts[severity]}<i class="severity-dot ${severity}"></i></span>`).join(" ");
  if (!items.length) {
    $("#findings-list").innerHTML = '<div class="table-empty">No prioritized exposure findings. Review the service inventory against intended architecture.</div>';
    return;
  }
  $("#findings-list").innerHTML = items.map((item) => `<article class="finding"><div class="finding-top"><span class="severity-badge ${esc(item.severity)}">${esc(item.severity)}</span><code>${esc(item.address)}:${esc(item.port)}</code></div><h4>${esc(item.title)}</h4><p>${esc(item.evidence)}</p><details><summary>Impact and remediation</summary><p><strong>Impact:</strong> ${esc(item.impact)}</p><p><strong>Action:</strong> ${esc(item.recommendation)}</p></details></article>`).join("");
}
