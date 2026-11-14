"use strict";

const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
const appearance = document.querySelector("#theme");
if (appearance) {
  appearance.value = document.documentElement.dataset.theme;
  appearance.addEventListener("change", () => {
    document.documentElement.dataset.theme = appearance.value;
    try { localStorage.setItem("shadowtrace-theme", appearance.value); } catch {}
  });
}

class RequestError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

async function post(url, data, {navigate = false, raw = false} = {}) {
  const headers = {"Content-Type": "application/json"};
  if (csrf) headers["X-CSRF-Token"] = csrf;
  let response;
  try {
    response = await fetch(url, {
      method: "POST", headers, body: JSON.stringify(data ?? {}),
      credentials: "same-origin", cache: "no-store", signal: AbortSignal.timeout(12000)
    });
  } catch {
    throw new RequestError("UNCERTAIN", "The response was interrupted. Check the latest saved state before retrying.");
  }
  if (response.redirected && navigate) {
    const target = new URL(response.url);
    if (target.origin !== location.origin) throw new RequestError("INVALID_TARGET", "The next page could not be verified.");
    location.assign(target.pathname + target.search);
    return {};
  }
  if (!response.ok) {
    if (response.status === 401) throw new RequestError("SIGN_IN_REQUIRED", "Your session expired. Sign in again.");
    const payload = await response.json().catch(() => ({}));
    throw new RequestError(payload.error?.code, payload.error?.message || "The request could not be completed. Try again.");
  }
  return raw ? response : response.json();
}

function feedback(parent, text, error = false) {
  const region = parent.querySelector(".feedback") ?? parent;
  region.textContent = text;
  region.hidden = !text;
  region.classList.toggle("error", error);
}

function busy(form, enabled) {
  if (enabled) form.setAttribute("aria-busy", "true");
  else form.removeAttribute("aria-busy");
  form.querySelectorAll("button,input,select,textarea").forEach(control => { control.disabled = enabled; });
}

function persistFlash(message, target = location.pathname, key = "st-flash") {
  try { sessionStorage.setItem(key, JSON.stringify({path: new URL(target, location.origin).pathname, message})); } catch {}
}

function takeFlash(key = "st-flash") {
  try {
    const value = JSON.parse(sessionStorage.getItem(key));
    sessionStorage.removeItem(key);
    return value?.path === location.pathname ? value.message : "";
  } catch { return ""; }
}

const flash = takeFlash();
const globalMessage = document.querySelector("#global-message");
const responseFeedback = document.querySelector("[data-response-feedback]");
const responseFlash = takeFlash("st-response-flash");
if (responseFeedback && responseFlash) feedback(responseFeedback, responseFlash);
document.querySelector("[data-logout]")?.addEventListener("click", async event => {
  event.currentTarget.disabled = true;
  try {
    await post("/auth/logout", {}, {navigate: true});
  } catch (error) {
    if (error.code === "SIGN_IN_REQUIRED") location.assign("/sign-in");
    else {
      feedback(globalMessage, error.message, true);
      document.querySelector("[data-logout]").disabled = false;
    }
  }
});

document.querySelector("[data-reload]")?.addEventListener("click", () => location.reload());
const demo = document.querySelector("[data-demo-form]");
demo?.addEventListener("submit", async event => {
  event.preventDefault();
  if (!event.submitter) return;
  const identity = event.submitter.value;
  busy(demo, true);
  feedback(demo, "Signing in…");
  try { await post("/auth/demo", {identity, next: demo.dataset.next}, {navigate: true}); }
  catch (error) { feedback(demo, error.message, true); busy(demo, false); }
});

const review = document.querySelector("[data-review]");
const rules = document.querySelector("[data-rules]:has(button[type=reset])");
const workForm = review || rules;
if (workForm) {
  const values = () => Object.fromEntries(new FormData(workForm));
  let lastAttempt;
  const reloadButton = workForm.querySelector(".refresh-draft");
  const originalDefaults = values();
  const syncReason = () => {
    if (review) review.querySelector("[data-close-reason]").hidden =
      !["resolved", "dismissed"].includes(review.elements.status.value);
  };
  syncReason();
  review?.elements.status.addEventListener("change", syncReason);
  if (flash) feedback(workForm, flash);
  workForm.addEventListener("reset", () => {
    feedback(workForm, ""); reloadButton.hidden = true;
    queueMicrotask(syncReason);
  });
  workForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (workForm.getAttribute("aria-busy")) return;
    const data = values();
    data.version = Number(workForm.dataset.revision);
    if (review) {
      data.note = data.note.trim();
      if (["resolved", "dismissed"].includes(data.status) && !data.note) {
        feedback(workForm, "Enter a note before closing this case.", true);
        workForm.elements.note.focus();
        return;
      }
      const closing = ["resolved", "dismissed"].includes(data.status);
      if (closing && !data.disposition) {
        feedback(workForm, "Choose a close reason.", true);
        workForm.elements.disposition.focus();
        return;
      }
      data.disposition = closing ? data.disposition : null;
      const same = lastAttempt && lastAttempt.status === data.status &&
        lastAttempt.note === data.note && lastAttempt.disposition === data.disposition;
      data.mutation_id = same ? lastAttempt.mutation_id : (lastAttempt ? crypto.randomUUID() : workForm.dataset.mutation);
    } else {
      data.view_limit = Number(data.view_limit);
      data.export_limit = Number(data.export_limit);
    }
    lastAttempt = data;
    busy(workForm, true);
    feedback(workForm, "Saving…");
    try {
      const result = await post(workForm.dataset.url, data);
      persistFlash(result.message);
      location.reload();
    } catch (error) {
      busy(workForm, false);
      feedback(workForm, error.message, true);
      reloadButton.hidden = !["STALE_CASE", "STALE_RULES", "UNCERTAIN"].includes(error.code);
      if (error.code === "SIGN_IN_REQUIRED") {
        reloadButton.hidden = false;
        reloadButton.textContent = "Sign in again";
        reloadButton.dataset.signIn = "true";
      }
    }
  });
  reloadButton.addEventListener("click", async () => {
    if (reloadButton.dataset.signIn) {
      location.assign("/sign-in?next=" + encodeURIComponent(location.pathname));
      return;
    }
    const current = values();
    busy(workForm, true);
    try {
      const response = await fetch(location.href, {cache: "no-store", signal: AbortSignal.timeout(10000)});
      if (!response.ok || response.redirected) throw new Error("Reload this page to continue.");
      const fresh = new DOMParser().parseFromString(await response.text(), "text/html");
      const newForm = fresh.querySelector(review ? "[data-review]" : "[data-rules]");
      if (!newForm) throw new Error("The latest saved state is unavailable.");
      const committed = review && lastAttempt && [...fresh.querySelectorAll("[data-completed]")]
        .some(entry => entry.dataset.completed === lastAttempt.mutation_id);
      const ruleCommitted = rules && lastAttempt && Number(newForm.dataset.revision) === lastAttempt.version + 1 &&
        Number(newForm.elements.view_limit.value) === lastAttempt.view_limit &&
        Number(newForm.elements.export_limit.value) === lastAttempt.export_limit;
      if (committed || ruleCommitted) {
        persistFlash(review ? "Review saved." : "Rules saved.");
        location.reload();
        return;
      }
      workForm.dataset.revision = newForm.dataset.revision;
      if (review) {
        workForm.dataset.mutation = newForm.dataset.mutation;
        const currentStatus = document.querySelector(".case-meta .label");
        if (currentStatus) currentStatus.textContent = fresh.querySelector(".case-meta .label")?.textContent || "";
        const history = document.querySelector(".review-history");
        if (history && fresh.querySelector(".review-history")) history.replaceWith(fresh.querySelector(".review-history"));
        for (const selector of [".findings", ".timeline-panel"]) {
          const latest = fresh.querySelector(selector);
          if (latest) document.querySelector(selector)?.replaceWith(latest);
        }
      } else {
        const latest = fresh.querySelector(".panel-head p");
        const previous = document.querySelector(".panel-head p");
        if (latest && previous) previous.textContent = latest.textContent;
      }
      for (const name of Object.keys(originalDefaults)) {
        const control = workForm.elements.namedItem(name);
        const server = newForm.elements.namedItem(name);
        if (!control || !server) continue;
        if (control.tagName === "SELECT") {
          [...control.options].forEach(option => { option.defaultSelected = option.value === server.value; });
        } else control.defaultValue = server.value;
        control.value = current[name];
      }
      const currentOwner = document.querySelector("[data-owner]");
      const freshOwner = fresh.querySelector("[data-owner]");
      if (currentOwner && freshOwner) {
        const select = currentOwner.elements.assignee;
        select.replaceChildren(...freshOwner.elements.assignee.options);
        select.value = freshOwner.elements.assignee.value;
        currentOwner.dataset.revision = freshOwner.dataset.revision;
      }
      lastAttempt = undefined;
      syncReason();
      reloadButton.hidden = true;
      const summary = review
        ? "Latest case loaded. Your draft is still here."
        : "Current saved thresholds: " + newForm.elements.view_limit.value + " views and " +
          newForm.elements.export_limit.value + " exports. Your draft is still here.";
      feedback(workForm, summary);
    } catch (error) {
      feedback(workForm, error.message || "The latest saved state could not be loaded.", true);
    } finally { busy(workForm, false); }
  });
}

const create = document.querySelector("#key-create");
const revoke = document.querySelector("#key-revoke");
const keyFeedback = document.querySelector("#key-feedback");
let returnFocus;
let refreshKeys = false;
if (keyFeedback && flash) feedback(keyFeedback, flash);
function open(dialog, trigger) {
  returnFocus = trigger;
  dialog.showModal();
}
document.querySelector("[data-open=key-create]")?.addEventListener("click", event => open(create, event.currentTarget));
document.querySelectorAll("[data-revoke]").forEach(button => button.addEventListener("click", () => {
  revoke.dataset.id = button.dataset.id;
  revoke.querySelector("[data-key-label]").textContent = button.dataset.label;
  open(revoke, button);
}));
for (const dialog of [create, revoke].filter(Boolean)) {
  dialog.querySelectorAll("[data-close]").forEach(button => button.addEventListener("click", () => dialog.close()));
  dialog.addEventListener("cancel", event => { if (dialog.querySelector('[aria-busy="true"]')) event.preventDefault(); });
  dialog.addEventListener("close", () => {
    dialog.querySelector("form").reset();
    dialog.querySelectorAll(".feedback").forEach(region => feedback(region, ""));
    if (dialog === create) {
      create.querySelector("[data-secret]").value = "";
      create.querySelector("[data-secret-view]").hidden = true;
      create.querySelector("form").hidden = false;
      create.querySelector("h2").textContent = "Create integration key";
    }
    returnFocus?.focus();
    if (refreshKeys) location.reload();
  });
}
const createForm = create?.querySelector("form");
function showKeyFields() {
  const purpose = createForm.elements.purpose.value;
  const signing = createForm.querySelector("[data-key-signing]");
  const source = createForm.querySelector("[data-key-source]");
  signing.hidden = purpose !== "receipts";
  signing.disabled = signing.hidden;
  source.hidden = purpose !== "impact";
  createForm.elements.source_key_id.disabled = source.hidden;
  createForm.elements.source_key_id.required = !source.hidden;
}
if (createForm) {
  createForm.elements.purpose.addEventListener("change", showKeyFields);
  createForm.addEventListener("reset", () => queueMicrotask(showKeyFields));
  showKeyFields();
}
createForm?.addEventListener("submit", async event => {
  event.preventDefault();
  const label = createForm.elements.label.value.trim();
  if (!label) { feedback(createForm, "Enter a key name of 1–60 characters.", true); return; }
  const fields = Object.fromEntries([...new FormData(createForm)].filter(([, value]) => value !== ""));
  busy(createForm, true);
  feedback(createForm, "Creating key…");
  try {
    const result = await post(create.dataset.base, {...fields, label});
    createForm.hidden = true;
    create.querySelector("h2").textContent = "Copy your integration key";
    create.querySelector("[data-secret-view]").hidden = false;
    create.querySelector("[data-secret]").value = result.key;
    create.querySelector("[data-copy]").focus();
    persistFlash("Integration key created.");
    refreshKeys = true;
  } catch (error) {
    feedback(createForm, error.message, true);
    if (error.code === "UNCERTAIN") refreshKeys = true;
  } finally { busy(createForm, false);
    showKeyFields(); }
});
create?.querySelector("[data-copy]").addEventListener("click", async () => {
  const field = create.querySelector("[data-secret]");
  try {
    await navigator.clipboard.writeText(field.value);
    feedback(create.querySelector("[data-secret-view]"), "Key copied.");
  } catch {
    field.focus();
    field.select();
    feedback(create.querySelector("[data-secret-view]"), "Copy the selected key to your secret store.", true);
  }
});
const revokeForm = revoke?.querySelector("form");
revokeForm?.addEventListener("submit", async event => {
  event.preventDefault();
  busy(revokeForm, true);
  feedback(revokeForm, "Revoking key…");
  try {
    await post(revoke.dataset.base + "/" + revoke.dataset.id + "/revoke");
    refreshKeys = true;
    persistFlash("Integration key revoked.");
    revoke.close();
  } catch (error) { feedback(revokeForm, error.message, true); }
  finally { busy(revokeForm, false); }
});

window.addEventListener("pageshow", event => {
  if (event.persisted && (csrf || demo)) location.reload();
});

async function latestMarkup() {
  const response = await fetch(location.href, {cache: "no-store", signal: AbortSignal.timeout(10000)});
  if (!response.ok || response.redirected) {
    throw new RequestError("UNAVAILABLE", "The latest page could not be loaded. Reload to try again.");
  }
  return new DOMParser().parseFromString(await response.text(), "text/html");
}

const demoPanel = document.querySelector("[data-demo-run]");
if (demoPanel) {
  const caseLink = demoPanel.querySelector("[data-case-link]");
  const traceLink = demoPanel.querySelector("[data-trace-link]");
  const labels = {normal: "Run normal activity", incident: "Run suspicious export",
    lineage: "Run record lineage demo"};
  let retry;
  for (const button of demoPanel.querySelectorAll("[data-scenario]")) {
    button.addEventListener("click", async () => {
      const scenario = button.dataset.scenario;
      const run = retry?.scenario === scenario ? retry : {
        scenario, run_id: crypto.randomUUID(), started_at: new Date().toISOString()
      };
      busy(demoPanel, true);
      caseLink.hidden = true;
      traceLink.hidden = true;
      feedback(demoPanel, "Sending synthetic events…");
      try {
        const data = await post(demoPanel.dataset.url, run);
        retry = undefined;
        if (data.case) {
          caseLink.href = data.case;
          caseLink.hidden = false;
        }
        if (data.trace) {
          traceLink.href = data.trace;
          traceLink.hidden = false;
        }
        const delivered = data.accepted + data.replayed;
        const message = scenario === "normal"
          ? delivered + " routine events delivered. Open Activity to inspect them."
          : data.trace
            ? delivered + " audit events and a destination receipt delivered."
          : data.case
            ? delivered + " events delivered. Open the case to review the evidence and baseline."
            : delivered + " events delivered. The current thresholds did not open a case.";
        feedback(demoPanel, message);
        const fresh = await latestMarkup().catch(() => null);
        for (const selector of [".metrics", ".chart-panel", ".records"]) {
          const updated = fresh?.querySelector(selector);
          if (updated) document.querySelector(selector)?.replaceWith(updated);
        }
      } catch (error) {
        retry = ["UNCERTAIN", "DEMO_DELIVERY", "DEMO_RATE", "RATE_LIMITED", "TEMPORARY_FAILURE"].includes(error.code)
          ? run : undefined;
        feedback(demoPanel, error.message, true);
      } finally {
        busy(demoPanel, false);
        for (const control of demoPanel.querySelectorAll("[data-scenario]")) {
          const original = labels[control.dataset.scenario];
          control.textContent = retry?.scenario === control.dataset.scenario ? "Retry this run" : original;
        }
        button.focus();
      }
    });
  }
}

const owner = document.querySelector("[data-owner]");
if (owner) {
  const control = owner.elements.assignee;
  const refresh = owner.querySelector("[data-owner-refresh]");
  owner.addEventListener("submit", async event => {
    event.preventDefault();
    const version = Number(owner.dataset.revision);
    const assignee = control.value || null;
    busy(owner, true);
    feedback(owner, "Saving owner…");
    let focus = event.submitter;
    try {
      const data = await post(owner.dataset.url, {version, assignee_id: assignee});
      owner.dataset.revision = String(data.version);
      if (data.version === version + 1 && Number(review.dataset.revision) === version) {
        review.dataset.revision = String(data.version);
      }
      refresh.hidden = true;
      feedback(owner, data.message);
    } catch (error) {
      feedback(owner, error.message, true);
      refresh.hidden = !["STALE_CASE", "UNCERTAIN", "INVALID_OWNER"].includes(error.code);
      if (!refresh.hidden) focus = refresh;
    } finally {
      busy(owner, false);
      focus?.focus();
    }
  });
  refresh.addEventListener("click", async () => {
    busy(owner, true);
    try {
      const fresh = await latestMarkup();
      const updated = fresh.querySelector("[data-owner]");
      if (!updated) throw new RequestError("UNAVAILABLE", "The case is no longer available.");
      control.replaceChildren(...updated.elements.assignee.options);
      control.value = updated.elements.assignee.value;
      owner.dataset.revision = updated.dataset.revision;
      refresh.hidden = true;
      feedback(owner, "Latest owner loaded.");
    } catch (error) {
      feedback(owner, error.message, true);
    } finally {
      busy(owner, false);
      control.focus();
    }
  });
}

const evidence = document.querySelector("[data-evidence]");
evidence?.addEventListener("click", async () => {
  const status = document.querySelector("[data-download-status]");
  evidence.disabled = true;
  feedback(status, "Preparing evidence…");
  try {
    const response = await post(evidence.dataset.evidence, {}, {raw: true});
    const file = await response.blob();
    const contents = JSON.parse(await file.text());
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = response.headers.get("content-disposition")?.match(/filename="([^"]+)"/)?.[1] || "shadowtrace-evidence.json";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    feedback(status, "Evidence package prepared. SHA-256: " + contents.sha256);
  } catch (error) {
    feedback(status, error.message, true);
  } finally { evidence.disabled = false; }
});

const replayPanel = document.querySelector("[data-replay-result]");
if (replayPanel && rules) {
  const status = replayPanel.querySelector("[data-replay-status]");
  const details = replayPanel.querySelector("[data-replay-details]");
  const examples = replayPanel.querySelector("[data-replay-examples]");
  const list = examples.querySelector("ul");
  const preview = rules.querySelector("[data-preview]");
  const number = new Intl.NumberFormat("en");
  const utc = new Intl.DateTimeFormat("en", {dateStyle: "medium", timeStyle: "short", timeZone: "UTC"});
  const clear = () => {
    details.hidden = true;
    feedback(status, "Use Preview impact to see how many events would match each rule.");
  };
  rules.addEventListener("input", clear);
  rules.addEventListener("reset", clear);
  preview.addEventListener("click", async () => {
    if (!rules.reportValidity()) return;
    const payload = {
      version: Number(rules.dataset.revision),
      view_limit: rules.elements.view_limit.valueAsNumber,
      export_limit: rules.elements.export_limit.valueAsNumber,
    };
    busy(rules, true);
    details.hidden = true;
    feedback(status, "Replaying recent events…");
    try {
      const result = await post(rules.dataset.url + "/replay", payload);
      if (result.evaluated === 0) {
        feedback(status, "No successful events were available in the evaluation period.");
        return;
      }
      for (const rule of ["view", "export"]) {
        const counts = result.counts[rule];
        const cells = replayPanel.querySelectorAll('[data-rule="' + rule + '"] td');
        ["current", "proposed", "added", "removed"].forEach((field, index) => {
          cells[index].textContent = number.format(counts[field]);
        });
      }
      list.replaceChildren();
      for (const item of result.changes) {
        const row = document.createElement("li");
        const name = document.createElement("strong");
        name.textContent = item.change === "added" ? "New match" : "Removed match";
        row.append(name, " · " + item.actor + " · " + number.format(item.observed) + " " +
          item.resource + (item.action === "view" ? " views in five minutes" : " records in one export") +
          " · " + utc.format(new Date(item.received_at)) + " UTC");
        list.append(row);
      }
      examples.hidden = !result.changes.length;
      details.hidden = false;
      const period = utc.format(new Date(result.starts)) + " to " + utc.format(new Date(result.ends)) + " UTC";
      feedback(status, number.format(result.evaluated) + " events evaluated, " + period + ". " +
        (result.truncated ? "The 5,000-event cap shortened the window. " : "") +
        "Counts are rule matches. Your settings are unchanged.");
    } catch (error) {
      feedback(status, error.message, true);
    } finally {
      busy(rules, false);
      preview.focus();
    }
  });
}

document.addEventListener("submit", async event => {
  const form = event.target;
  if (!form.matches("form[data-response-action]")) return;
  event.preventDefault();
  const fields = Object.fromEntries(new FormData(form));
  busy(form, true);
  feedback(form, "Saving…");
  try {
    const result = await post(form.dataset.responseAction, fields);
    persistFlash(result.message, result.location, "st-response-flash");
    if (result.location) location.assign(result.location);
    else location.reload();
  } catch (error) {
    feedback(form, error.message, true);
    busy(form, false);
  }
});

const followup = document.querySelector("form[data-followup-save]");
followup?.querySelector("[data-save-view]").addEventListener("click", async () => {
  const fields = Object.fromEntries(new FormData(followup));
  busy(followup, true);
  feedback(followup, "Saving filters…");
  try {
    const result = await post(followup.dataset.followupSave, fields);
    persistFlash(result.message, result.location, "st-response-flash");
    location.assign(result.location);
  } catch (error) {
    feedback(followup, error.message, true);
    busy(followup, false);
  }
});

const protectionPolicy = document.querySelector("[data-protection-policy]");
if (protectionPolicy) {
  const policyFeedback = protectionPolicy.querySelector(".feedback");
  const policyFlash = takeFlash("st-protection-flash");
  if (policyFlash) feedback(policyFeedback, policyFlash);
  protectionPolicy.addEventListener("submit", async event => {
    event.preventDefault();
    const fields = Object.fromEntries(new FormData(protectionPolicy));
    const request = {
      mode: fields.mode,
      version: Number(protectionPolicy.dataset.version),
      export_limit: Number(fields.export_limit),
      download_limit: Number(fields.download_limit),
      share_limit: Number(fields.share_limit),
      cumulative_limit: Number(fields.cumulative_limit),
      approval_threshold: Number(fields.approval_threshold),
      destinations: fields.destinations.split("\n").map(line => line.trim()).filter(Boolean)
    };
    busy(protectionPolicy, true);
    feedback(protectionPolicy, "Saving policy…");
    try {
      const result = await post(protectionPolicy.dataset.protectionPolicy, request);
      persistFlash(result.message, location.pathname, "st-protection-flash");
      location.reload();
    } catch (error) {
      feedback(protectionPolicy, error.message, true);
      busy(protectionPolicy, false);
    }
  });
}

const protectionDemo = document.querySelector("[data-protection-demo]");
protectionDemo?.addEventListener("submit", async event => {
  event.preventDefault();
  const list = protectionDemo.querySelector(".protection-results");
  busy(protectionDemo, true);
  list.hidden = true;
  feedback(protectionDemo, "Checking both transfers…");
  try {
    const result = await post(protectionDemo.dataset.protectionDemo, {});
    list.replaceChildren();
    for (const item of result.outcomes) {
      const entry = document.createElement("li");
      const title = document.createElement("h3");
      const detail = document.createElement("p");
      title.textContent = item.title;
      detail.textContent = item.detail;
      entry.append(title, detail);
      list.append(entry);
    }
    list.hidden = false;
    try {
      const fresh = await latestMarkup();
      for (const selector of ["[data-protection-metrics]", "#protection-decisions"]) {
        const updated = fresh.querySelector(selector);
        if (updated) document.querySelector(selector).replaceWith(updated);
      }
      feedback(protectionDemo, "Transfer checks finished. Decision history updated.");
    } catch {
      feedback(protectionDemo, "Transfer checks finished. Reload to see the latest decision history.");
    }
  } catch (error) {
    feedback(protectionDemo, error.message, true);
  } finally {
    busy(protectionDemo, false);
  }
});


const managed = document.querySelector("form[data-managed-demo]");
if (managed) {
  const draftKey = location.pathname + "/" + managed.dataset.user + "/demo";
  const variant = managed.elements.variant;
  const recipient = managed.elements.recipient;
  const sensitive = managed.elements.sensitive;
  const resultLink = managed.querySelector("[data-managed-result]");
  function newSample() {
    return {operation: crypto.randomUUID(), nominal_day: new Date().toISOString().slice(0,10)};
  }
  function syncRecipient() {
    recipient.disabled = variant.value !== "cloud";
    managed.querySelector("[data-demo-recipient]").hidden = recipient.disabled;
  }
  let sample;
  try { sample = JSON.parse(sessionStorage.getItem(draftKey)); } catch {}
  sample ??= newSample();
  if (sample.variant) variant.value = sample.variant;
  if (sample.recipient) recipient.value = sample.recipient;
  sensitive.checked = Boolean(sample.sensitive);
  syncRecipient();
  variant.addEventListener("change", syncRecipient);
  managed.querySelector("[data-new-occurrence]").addEventListener("click", () => {
    sample = newSample();
    try { sessionStorage.removeItem(draftKey); } catch {}
    resultLink.hidden = true;
    feedback(managed, "New sample ready.");
  });
  managed.addEventListener("submit", async event => {
    event.preventDefault();
    sample = {...sample, variant:variant.value, recipient:recipient.disabled ? null : recipient.value,
      sensitive:sensitive.checked};
    try { sessionStorage.setItem(draftKey, JSON.stringify(sample)); } catch {}
    busy(managed, true);
    resultLink.hidden = true;
    feedback(managed, "Checking the transfer…");
    try {
      const result = await post(managed.dataset.managedDemo, sample);
      feedback(managed, result.message + " Operation " + result.reference + ".");
      if (result.path) {
        resultLink.href = result.path;
        resultLink.hidden = false;
      }
      const fresh = await latestMarkup();
      for (const selector of ["[data-managed-transfers]", "[data-protection-metrics]", "#protection-decisions"]) {
        const updated = fresh.querySelector(selector);
        if (updated) document.querySelector(selector).replaceWith(updated);
      }
    } catch (error) {
      feedback(managed, error.message, true);
    } finally {
      busy(managed, false);
      syncRecipient();
    }
  });
}

document.addEventListener("click", async event => {
  const button = event.target.closest("[data-copy-cloud]");
  if (!button) return;
  const link = new URL(button.dataset.copyCloud, location.origin).href;
  const result = button.nextElementSibling;
  try {
    await navigator.clipboard.writeText(link);
    feedback(result, "Recipient link copied.");
  } catch {
    feedback(result, link);
  }
});
