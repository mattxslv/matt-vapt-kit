"use strict";
const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="mvk-token"]').content;
let projects = [], preview = null, activeJob = null, timer = null;
const text = (tag, value, className) => {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
};
function showError(message) {
  $("notice").textContent = message;
  $("notice").hidden = false;
  $("notice").scrollIntoView({block: "nearest"});
}
function clearError() { $("notice").hidden = true; }
async function api(path, data) {
  const response = await fetch(path, {
    method: data === undefined ? "GET" : "POST",
    headers: {"X-MVK-Token": token, ...(data === undefined ? {} : {"Content-Type": "application/json"})},
    body: data === undefined ? undefined : JSON.stringify(data), cache: "no-store",
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error || `Request failed (${response.status}). No success was assumed.`);
  }
  return response.json();
}
function stage(number) {
  [1, 2, 3].forEach((n) => {
    if (n === number) $(`step-${n}`).setAttribute("aria-current", "step");
    else $(`step-${n}`).removeAttribute("aria-current");
  });
  $("scope-form").hidden = number !== 1;
  $("approval-panel").hidden = number !== 2;
  $("result-panel").hidden = number !== 3;
}
function resetApproval() {
  preview = null;
  $("credential-fields").replaceChildren();
  $("consent").checked = false;
}
function selectedProject() { return projects.find((p) => p.id === $("project").value); }
function updateProject() {
  resetApproval();
  const project = selectedProject();
  $("target-info").hidden = !project;
  $("accounts").replaceChildren();
  if (!project) return;
  $("target").textContent = project.target;
  $("access").textContent = `Gateway: ${project.access}. Staging identity and permission must be confirmed by the owner.`;
  const roleOption = $("profile").querySelector('option[value="roles"]');
  roleOption.disabled = !project.accounts.length;
  if (roleOption.disabled) $("profile").value = "headers";
  const roles = $("profile").value === "roles";
  $("accounts-group").hidden = !roles;
  $("paths").value = roles ? project.routes.map((route) => route.path).join("\n") : "/";
  project.accounts.forEach((account) => {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox"; checkbox.value = account.id;
    label.append(checkbox, text("span", `${account.id} (${account.role})`));
    $("accounts").append(label);
  });
  $("project-note").textContent = project.access === "iap-browser" || project.access === "bearer"
    ? "This gateway mode needs the CLI. Mount a keyless IAP or public configuration to run it here."
    : "Configuration loaded read-only. No target has been contacted.";
}
async function loadProjects() {
  const result = await api("/api/projects");
  projects = result.projects.filter((p) => !p.error);
  $("project").replaceChildren();
  $("project").append(new Option(projects.length ? "Choose a project" : "No valid project configurations found", ""));
  projects.forEach((p) => $("project").append(new Option(`${p.name} · ${p.access}`, p.id)));
  const invalid = result.projects.filter((p) => p.error);
  if (invalid.length) showError(`${invalid.length} project configuration(s) could not be loaded. Fix the mounted YAML files.`);
}
function scopeRow(label, value) {
  $("approval-summary").append(text("dt", label), text("dd", value));
}
$("scope-form").addEventListener("submit", async (event) => {
  event.preventDefault(); clearError();
  const project = selectedProject();
  if (!project) { showError("Choose a project first."); return; }
  $("preview").disabled = true;
  $("preview").textContent = "Checking local prerequisites...";
  try {
    const profile = $("profile").value;
    const result = await api("/api/preview", {
      project: project.id, digest: project.digest, profile, owner: $("owner").value.trim(),
      minutes: Number($("minutes").value),
      paths: $("paths").value.split("\n").map((v) => v.trim()).filter(Boolean),
      accounts: [...$("accounts").querySelectorAll("input:checked")].map((input) => input.value),
    });
    preview = {project: project.id, profile, ...result};
    $("approval-summary").replaceChildren();
    scopeRow("Target", result.target);
    scopeRow("Profile", profile === "roles" ? "DTAP endpoint-role matrix" : "Header policy checks");
    scopeRow("Paths", result.approval.paths.join(", "));
    if (profile === "roles") scopeRow("Accounts", result.approval.role_accounts.join(", "));
    scopeRow("Expires", new Date(result.approval.expires_at).toLocaleString());
    scopeRow("Request bound", `At most ${result.maximum_requests} application requests, 2 seconds apart`);
    scopeRow("Config fingerprint", result.digest.slice(0, 16));
    $("credential-fields").replaceChildren();
    result.fields.forEach((field) => {
      const label = text("label", field.kind === "password" ? `QA password (${field.name})` : `QA email (${field.name})`);
      const input = document.createElement("input");
      input.type = field.kind; input.required = true; input.dataset.field = field.name;
      input.maxLength = field.kind === "password" ? 1024 : 254;
      input.autocomplete = "off"; input.spellcheck = false;
      label.append(input); $("credential-fields").append(label);
    });
    $("credential-note").hidden = !result.fields.length;
    $("consent").checked = false;
    stage(2);
    $("approval-title").tabIndex = -1; $("approval-title").focus();
  } catch (error) { showError(error.message); }
  finally { $("preview").disabled = false; $("preview").textContent = "Check prerequisites & review scope →"; }
});
$("back").addEventListener("click", () => { resetApproval(); stage(1); });
$("project").addEventListener("change", updateProject);
$("profile").addEventListener("change", updateProject);
$("run-form").addEventListener("submit", async (event) => {
  event.preventDefault(); clearError();
  if (!preview || !$("consent").checked) { showError("Review and explicitly approve the scope first."); return; }
  const credentials = {};
  $("credential-fields").querySelectorAll("input").forEach((input) => { credentials[input.dataset.field] = input.value; input.value = ""; });
  $("run").disabled = true;
  try {
    const job = await api("/api/jobs", {profile: preview.profile, project: preview.project,
      approval: preview.approval, credentials, acknowledge: true});
    resetApproval(); await follow(job.id);
  } catch (error) { showError(error.message); }
  finally {
    Object.keys(credentials).forEach((key) => { delete credentials[key]; });
    $("run").disabled = false;
  }
});
$("demo").addEventListener("click", async () => {
  clearError(); $("demo").disabled = true;
  try {
    const job = await api("/api/jobs", {profile: "demo", acknowledge: true});
    resetApproval(); await follow(job.id);
  } catch (error) { showError(error.message); }
  finally { $("demo").disabled = false; }
});
async function download(id, kind) {
  const response = await fetch(`/api/jobs/${id}/download/${kind}`, {headers: {"X-MVK-Token": token}});
  if (!response.ok) throw new Error("Artifact download failed. Refresh the run and try again.");
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url; link.download = `mvk-${id.slice(0, 8)}.${kind}`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
function displayJob(job) {
  stage(3);
  $("result-kicker").textContent = job.profile === "demo" ? "SYNTHETIC DEMONSTRATION" : job.profile.toUpperCase() + " / " + job.project;
  $("result-title").textContent = job.status === "running" ? "Working within your scope."
    : job.status === "completed" ? (job.assessment_status === "incomplete" ? "Finished, with coverage gaps." : "Your evidence is ready.")
    : "This run did not complete.";
  $("result-message").textContent = job.message;
  const details = $("result-details"); details.replaceChildren();
  if (job.profile === "demo") details.append(text("p", "Demo only. The findings below are synthetic examples, not vulnerabilities discovered on your system.", "caution"));
  if (job.findings) {
    const confirmed = job.findings.filter((f) => f.verification === "confirmed").length;
    details.append(text("p", `${job.findings.length} ${job.findings.length === 1 ? "finding" : "findings"} / ${confirmed} confirmed / ${(job.errors || []).length} errors`, "result-stat"));
    if (job.expected_cells) {
      const tested = job.cells.filter((c) => ["allowed", "denied", "confirmed"].includes(c.outcome)).length;
      const blocked = job.cells.filter((c) => c.outcome === "blocked").length;
      const inconclusive = job.cells.filter((c) => c.outcome === "inconclusive").length;
      details.append(text("p", `${tested}/${job.expected_cells} role cells assessed; ${blocked} blocked; ${inconclusive} inconclusive; ${job.expected_cells - job.cells.length} not attempted.`, "field-note"));
      const table = document.createElement("table"); table.className = "result-table";
      const head = document.createElement("thead"), row = document.createElement("tr");
      ["Account", "Path", "Outcome"].forEach((value) => { const th = text("th", value); th.scope = "col"; row.append(th); });
      head.append(row); table.append(head);
      const body = document.createElement("tbody");
      job.cells.forEach((cell) => {
        const tr = document.createElement("tr");
        [cell.account, cell.path, cell.outcome].forEach((value) => tr.append(text("td", value)));
        body.append(tr);
      });
      table.append(body); details.append(table);
    }
    job.findings.forEach((finding) => {
      const article = document.createElement("article"); article.className = "finding";
      article.append(text("small", `${finding.severity.toUpperCase()} / ${finding.verification}`),
        text("h3", finding.title), text("p", finding.impact), text("p", `Next action: ${finding.remediation}`));
      details.append(article);
    });
    if (!job.findings.length) details.append(text("p", "No findings in the recorded scope. This does not establish that the application is secure."));
    (job.errors || []).forEach((error) => details.append(text("p", `${error.path}: ${error.message}`, "caution")));
    if (job.cleanup?.length) {
      details.append(text("p", "Sign-out: " + job.cleanup.map((c) => `${c.account}: ${c.status}`).join("; "), "field-note"));
      details.append(text("p", "Acknowledgement is not proof of session revocation. Unconfirmed sessions may require manual cleanup.", "field-note"));
    }
    if (job.coverage) details.append(text("p", job.coverage.note, "field-note"));
  }
  $("downloads").replaceChildren();
  (job.downloads || []).forEach((kind) => {
    const button = text("button", `Download ${kind.toUpperCase()}`, kind === "pdf" ? "primary" : "secondary");
    button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await download(job.id, kind); } catch (error) { showError(error.message); }
      finally { button.disabled = false; }
    });
    $("downloads").append(button);
  });
  if (job.downloads?.length) details.append(text("p", "Downloads stay on your computer. Open the HTML file in a browser or the PDF in your document viewer. Review before sharing.", "field-note"));
}
async function follow(id) {
  activeJob = id;
  if (timer) clearTimeout(timer);
  const job = await api(`/api/jobs/${id}`);
  if (activeJob !== id) return;
  displayJob(job);
  if (job.status === "running") {
    timer = setTimeout(() => follow(id).catch((error) => showError(error.message)), 1500);
  } else { await loadHistory(); }
}
async function loadHistory() {
  const result = await api("/api/jobs");
  $("history").replaceChildren();
  if (!result.jobs.length) $("history").append(text("p", "No runs yet. Create a sample report to learn the flow.", "field-note"));
  result.jobs.forEach((job) => {
    const button = document.createElement("button"); button.type = "button"; button.className = "history-item";
    button.append(text("strong", job.profile === "demo" ? "Sample report" : job.project),
      text("small", `${job.status} · ${new Date(job.created_at).toLocaleString()}`));
    button.addEventListener("click", () => follow(job.id).catch((error) => showError(error.message)));
    $("history").append(button);
  });
}
$("refresh").addEventListener("click", () => loadHistory().catch((error) => showError(error.message)));
$("new-run").addEventListener("click", () => {
  if (timer) clearTimeout(timer);
  activeJob = null; resetApproval(); clearError(); stage(1);
});
Promise.all([loadProjects(), loadHistory()]).catch((error) => showError(error.message));
