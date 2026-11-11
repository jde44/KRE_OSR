/* Open Sovereign Router local demo.
 * This script never decides a route: every decision comes from the backend.
 * All dynamic text is rendered with textContent; no HTML is ever built from data.
 */
"use strict";

(function () {
  const state = { token: "", config: null, lastRequest: null, lastResult: null, lastApproval: null };
  const $ = (id) => document.getElementById(id);

  function readToken() {
    const match = /(?:^|[#&])t=([A-Za-z0-9_-]{20,128})/.exec(window.location.hash || "");
    if (match) {
      state.token = match[1];
      // Keep the token out of the address bar and history once read.
      window.history.replaceState(null, "", window.location.pathname);
    }
  }

  async function api(path, method, body) {
    const options = { method: method || "GET", headers: { "X-OSR-Demo-Token": state.token }, cache: "no-store", credentials: "omit" };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    let data = {};
    try { data = await response.json(); } catch (e) { data = {}; }
    if (!response.ok) {
      const error = new Error(data.error || ("Request failed with status " + response.status));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function facts(target, pairs) {
    const nodes = pairs.filter((p) => p[1] !== undefined && p[1] !== null && p[1] !== "").map(([label, value]) => {
      const row = el("div");
      row.append(el("dt", label), el("dd", value));
      return row;
    });
    target.replaceChildren(...nodes);
  }

  function setBanner(text, isError) {
    const banner = $("connection-status");
    banner.textContent = text;
    banner.classList.toggle("error", Boolean(isError));
  }

  function setFlow(states) {
    document.querySelectorAll("#flow li").forEach((item) => {
      const entry = states[item.dataset.step] || ["waiting", "waiting"];
      item.dataset.state = entry[0];
      item.querySelector(".step-state").textContent = entry[1];
    });
  }

  function renderModels(selected) {
    const rows = state.config.models.map((m) => {
      const row = el("tr");
      if (selected && m.model_id === selected) row.className = "selected";
      const name = el("td");
      name.append(el("span", m.model_id, "mono"));
      const where = m.kind === "local" ? "Local" : "Cloud (simulated)";
      const price = m.usd_per_million_tokens === 0 ? "$0 (local)" : "$" + m.usd_per_million_tokens.toFixed(2) + " / 1M tokens";
      row.append(name, el("td", where), el("td", m.capability), el("td", price));
      return row;
    });
    $("model-rows").replaceChildren(...rows);
  }

  function renderPresets() {
    const buttons = state.config.presets.map((preset) => {
      const button = el("button", null, "preset");
      button.type = "button";
      button.dataset.preset = preset.id;
      button.setAttribute("aria-pressed", "false");
      button.append(el("strong", preset.title), el("span", preset.summary));
      button.addEventListener("click", () => applyPreset(preset, button));
      return button;
    });
    $("preset-list").replaceChildren(...buttons);
  }

  function applyPreset(preset, button) {
    document.querySelectorAll(".preset").forEach((b) => b.setAttribute("aria-pressed", String(b === button)));
    $("message").value = preset.message;
    document.querySelector('input[name="sensitivity"][value="' + preset.sensitivity + '"]').checked = true;
    $("capability").value = preset.capability;
    $("max-tokens").value = String(preset.max_tokens);
    updateCount();
    runRequest();
  }

  function updateCount() {
    $("message-count").textContent = $("message").value.length + " / " + state.config.limits.max_message_chars;
  }

  function readForm() {
    const message = $("message").value;
    const sensitivity = document.querySelector('input[name="sensitivity"]:checked').value;
    const capability = $("capability").value;
    const raw = $("max-tokens").value.trim();
    const maxTokens = /^[0-9]+$/.test(raw) ? Number(raw) : NaN;
    const limit = state.config.limits;
    if (!message.trim()) return { error: "Enter some synthetic request text, or pick a preset." };
    if (message.length > limit.max_message_chars) return { error: "The request text is longer than " + limit.max_message_chars + " characters." };
    if (!Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > limit.max_output_tokens) return { error: "The output-token budget must be a whole number from 1 to " + limit.max_output_tokens + "." };
    return { request: { message: message, sensitivity: sensitivity, capability: capability, max_tokens: maxTokens } };
  }

  function showFormError(text) {
    const box = $("form-error");
    box.textContent = text || "";
    box.hidden = !text;
  }

  const CAPABILITY_NAME = { 1: "basic", 2: "standard", 3: "advanced" };

  const OUTCOME_LABEL = {
    routed: "Routed",
    approval_required: "Approval required",
    blocked: "Blocked",
    error: "Rejected",
  };

  function renderClassification(request, result) {
    facts($("classification"), [
      ["Sensitivity", request.sensitivity],
      ["Capability", request.capability],
      ["Output budget", request.max_tokens + " tokens"],
      ["Request ID", result.request_id || "—"],
      ["Your text (shown as typed)", request.message],
    ]);
  }

  function renderDecision(result) {
    const box = $("decision");
    const badgeText = result.outcome === "routed" && result.decision.provider === "cloud" ? "Routed to cloud with approval"
      : result.outcome === "routed" ? "Routed locally" : OUTCOME_LABEL[result.outcome];
    const badge = el("p", badgeText, "outcome " + result.outcome);
    const explanation = el("p", result.explanation);
    const details = el("dl", null, "facts");
    const d = result.decision;
    facts(details, [
      ["Provider", d.provider || "none (not executed)"],
      ["Model", d.model || "none"],
      ["Reason code", d.reason_code],
      ["Approval verified", d.approval_verified ? "yes" : "no"],
      ["Router HTTP status", String(result.http_status)],
    ]);
    const nodes = [badge, explanation, details];
    if (result.response_preview) {
      nodes.push(el("p", "Synthetic provider output", "help"), el("p", result.response_preview, "preview"));
    }
    box.replaceChildren(...nodes);
  }

  function renderApproval(result) {
    const box = $("approval");
    if (result.outcome === "approval_required" && result.approval_request) {
      const b = result.approval_request.bindings;
      const intro = el("p", "Approve only if this is the single request you intend to send to the cloud model. The approval is bound to these exact values, expires quickly and can be used once.");
      const list = el("dl", null, "facts bindings");
      facts(list, [
        ["Destination", b.provider_id + " / " + b.model_id],
        ["Sensitivity", b.sensitivity],
        ["Capability", (CAPABILITY_NAME[b.required_capability] || "level") + " (" + b.required_capability + ")"],
        ["Output budget", String(result.approval_request.max_tokens) + " tokens"],
        ["Payload digest", b.payload_sha256.slice(0, 16) + "…"],
        ["Request ID", b.request_id],
      ]);
      const approve = el("button", "Approve this single request", "approve");
      approve.type = "button";
      approve.addEventListener("click", () => approveAndRun(result));
      const cancel = el("button", "Cancel", "cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => {
        box.replaceChildren(el("p", "Cancelled. Nothing was sent to the cloud model.", "placeholder"));
        setFlow({ classify: ["done", "classified"], policy: ["done", "evaluated"], route: ["blocked", "cancelled by approver"], audit: ["done", "decision recorded"] });
      });
      const actions = el("div", null, "actions");
      actions.append(approve, cancel);
      box.replaceChildren(intro, list, actions);
      return;
    }
    if (result.outcome === "routed" && result.decision.approval_verified) {
      const replay = el("button", "Try to reuse this approval", "secondary");
      replay.type = "button";
      replay.addEventListener("click", replayApproval);
      box.replaceChildren(el("p", "Approved and used once. A second use of the same approval is refused by the router."), replay);
      return;
    }
    if (result.decision && result.decision.reason_code === "invalid_approval") {
      box.replaceChildren(el("p", "Refused: this approval was already used, expired or does not match the request. Nothing was executed."));
      return;
    }
    if (result.outcome === "blocked" && result.decision.reason_code === "sensitive_local_unavailable") {
      box.replaceChildren(el("p", "Not available: " + result.decision.reason_code + ". Confidential and restricted data can never be approved for cloud routing."));
      return;
    }
    box.replaceChildren(el("p", "No approval needed: this request did not require a cloud route.", "placeholder"));
  }

  function renderEstimate(result) {
    const e = result.estimate;
    const box = $("estimate");
    const list = el("dl", null, "facts");
    facts(list, [
      ["Input tokens (est.)", String(e.input_tokens_estimated)],
      ["Output budget", e.output_tokens_budget + " tokens"],
      ["Selected model price", e.usd_per_million_tokens === undefined ? "—" : "$" + e.usd_per_million_tokens.toFixed(2) + " / 1M tokens (synthetic)"],
      ["Cost (est.)", e.executed ? "$" + e.cost_usd_estimated.toFixed(6) : "$0 (not executed)"],
      ["Same request on cloud (est.)", "$" + e.cloud_reference_cost_usd.toFixed(6)],
    ]);
    box.replaceChildren(list, el("p", e.label, "help"));
  }

  function flowFor(result) {
    const d = result.decision;
    if (result.outcome === "routed") {
      return { classify: ["done", "classified"], policy: ["done", "evaluated"], route: ["done", d.model + " (" + d.provider + ")"], audit: ["done", "decision + outcome recorded"] };
    }
    if (result.outcome === "approval_required") {
      return { classify: ["done", "classified"], policy: ["done", "evaluated"], route: ["pending", "awaiting human approval"], audit: ["done", "decision recorded"] };
    }
    return { classify: ["done", "classified"], policy: ["done", "evaluated"], route: ["blocked", "blocked: " + (d.reason_code || "rejected")], audit: ["done", "decision recorded"] };
  }

  async function refreshAudit(highlight) {
    const data = await api("/demo/audit");
    const rows = data.events.map((e) => {
      const row = el("tr");
      if (highlight && e.request_id === highlight) row.className = "selected";
      const route = e.provider_id ? e.provider_id + " / " + e.model_id : "—";
      const result = e.outcome ? e.status + " · " + e.outcome : e.status + " · " + e.reason_code;
      const id = el("td");
      id.append(el("span", e.request_id.slice(0, 8) + "…", "mono"));
      row.append(el("td", e.timestamp.replace("T", " ").replace(/\.\d+/, "").replace("Z", "")), id, el("td", e.phase), el("td", result), el("td", route), el("td", e.approval_verified ? "yes" : "no"));
      return row;
    });
    if (!rows.length) {
      const empty = el("tr");
      const cell = el("td", "No events yet.", "placeholder");
      cell.colSpan = 6;
      empty.append(cell);
      rows.push(empty);
    }
    $("audit-rows").replaceChildren(...rows);
  }

  function render(request, result) {
    state.lastRequest = request;
    state.lastResult = result;
    renderClassification(request, result);
    renderDecision(result);
    renderApproval(result);
    renderEstimate(result);
    renderModels(result.decision.model);
    setFlow(flowFor(result));
  }

  async function send(request, approval) {
    const body = Object.assign({}, request);
    if (approval) body.approval = approval;
    setBusy(true);
    try {
      const result = await api("/demo/route", "POST", body);
      render(request, result);
      await refreshAudit(result.request_id);
      return result;
    } catch (err) {
      showFormError(err.message);
      return null;
    } finally {
      setBusy(false);
    }
  }

  function runRequest() {
    showFormError("");
    const parsed = readForm();
    if (parsed.error) { showFormError(parsed.error); return; }
    state.lastApproval = null;
    send(parsed.request);
  }

  async function approveAndRun(result) {
    try {
      const granted = await api("/demo/approve", "POST", { bindings: result.approval_request.bindings });
      state.lastApproval = { token: granted.approval_token, request_id: granted.request_id };
      await send(state.lastRequest, state.lastApproval);
    } catch (err) {
      showFormError(err.message);
    }
  }

  function replayApproval() {
    if (state.lastApproval && state.lastRequest) send(state.lastRequest, state.lastApproval);
  }

  function setBusy(busy) {
    $("run-button").disabled = busy;
    $("run-button").textContent = busy ? "Routing…" : "Run routing policy";
  }

  async function resetDemo() {
    try {
      await api("/demo/reset", "POST", {});
      state.lastRequest = state.lastResult = state.lastApproval = null;
      $("request-form").reset();
      updateCount();
      showFormError("");
      document.querySelectorAll(".preset").forEach((b) => b.setAttribute("aria-pressed", "false"));
      $("classification").replaceChildren((() => { const r = el("div"); r.append(el("dt", "Status"), el("dd", "Run a request to see its classification.")); return r; })());
      $("decision").replaceChildren(el("p", "No request yet.", "placeholder"));
      $("approval").replaceChildren(el("p", "Cloud routes need explicit approval for each request. Nothing to approve yet.", "placeholder"));
      $("estimate").replaceChildren(el("p", "Estimates appear after a decision.", "placeholder"));
      setFlow({});
      renderModels(null);
      await refreshAudit(null);
      setBanner("Demo reset: a fresh router with new keys, an empty audit log and no pending approvals.");
      $("request-heading").focus();
    } catch (err) {
      setBanner("Reset failed: " + err.message, true);
    }
  }

  async function init() {
    readToken();
    if (!state.token) {
      setBanner("No demo token found. Open the full URL printed by ./scripts/demo_ui.sh.", true);
      return;
    }
    try {
      state.config = await api("/demo/config");
    } catch (err) {
      setBanner("Could not reach the local router: " + err.message, true);
      return;
    }
    setBanner(state.config.notice);
    renderPresets();
    renderModels(null);
    updateCount();
    setFlow({});
    $("message").addEventListener("input", updateCount);
    $("request-form").addEventListener("submit", (event) => { event.preventDefault(); runRequest(); });
    $("reset-button").addEventListener("click", resetDemo);
    await refreshAudit(null);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
