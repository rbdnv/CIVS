const AUTH_STORAGE_KEY = "civs_dashboard_auth";

const views = {
  contexts: { title: "Contexts", kicker: "Memory" },
  verification: { title: "Verification", kicker: "Integrity" },
  rag: { title: "RAG ingest", kicker: "Untrusted input" },
  audit: { title: "Audit", kicker: "History" },
  security: { title: "Security events", kicker: "Incidents" },
  demo: { title: "Demo", kicker: "Showcase" },
};

const demoPages = [
  { title: "Compare", route: "/demo/compare", status: "Ready" },
  { title: "Live compare", route: "/demo/live-compare", status: "Requires LLM config" },
  { title: "Demoapp playground", route: "/demo/demoapp-playground", status: "Ready" },
  { title: "Agent reports", route: "/admin/interactions", status: "Admin" },
];

const state = {
  activeView: "contexts",
  token: "",
  role: "",
  userId: "",
  username: "",
  contexts: [],
  selectedContextId: "",
  chain: [],
  verification: null,
  rag: null,
  audit: [],
  security: [],
};

const elements = {
  navButtons: Array.from(document.querySelectorAll("[data-view]")),
  panels: Array.from(document.querySelectorAll("[data-panel]")),
  sectionTitle: document.getElementById("sectionTitle"),
  sectionKicker: document.getElementById("sectionKicker"),
  statusLine: document.getElementById("statusLine"),
  loginForm: document.getElementById("loginForm"),
  loginFields: document.querySelector(".login-fields"),
  usernameInput: document.getElementById("usernameInput"),
  passwordInput: document.getElementById("passwordInput"),
  loginButton: document.getElementById("loginButton"),
  logoutButton: document.getElementById("logoutButton"),
  authState: document.getElementById("authState"),
  contextCreateForm: document.getElementById("contextCreateForm"),
  contextCreateState: document.getElementById("contextCreateState"),
  contextContentInput: document.getElementById("contextContentInput"),
  contextSessionInput: document.getElementById("contextSessionInput"),
  contextTypeInput: document.getElementById("contextTypeInput"),
  contextPriorityInput: document.getElementById("contextPriorityInput"),
  contextsFilterForm: document.getElementById("contextsFilterForm"),
  contextsSessionFilter: document.getElementById("contextsSessionFilter"),
  contextsUserFilter: document.getElementById("contextsUserFilter"),
  contextsLimitFilter: document.getElementById("contextsLimitFilter"),
  contextsTableBody: document.getElementById("contextsTableBody"),
  contextsCount: document.getElementById("contextsCount"),
  contextDetails: document.getElementById("contextDetails"),
  verifySelectedContextButton: document.getElementById("verifySelectedContextButton"),
  chainTableBody: document.getElementById("chainTableBody"),
  chainState: document.getElementById("chainState"),
  verifyForm: document.getElementById("verifyForm"),
  verifyContextIdInput: document.getElementById("verifyContextIdInput"),
  verifyTamperingInput: document.getElementById("verifyTamperingInput"),
  verifyReplayInput: document.getElementById("verifyReplayInput"),
  verificationState: document.getElementById("verificationState"),
  verificationResult: document.getElementById("verificationResult"),
  ragForm: document.getElementById("ragForm"),
  ragFileNameInput: document.getElementById("ragFileNameInput"),
  ragDataSourceInput: document.getElementById("ragDataSourceInput"),
  ragContentInput: document.getElementById("ragContentInput"),
  ragState: document.getElementById("ragState"),
  ragResult: document.getElementById("ragResult"),
  auditFilterForm: document.getElementById("auditFilterForm"),
  auditUserFilter: document.getElementById("auditUserFilter"),
  auditActionFilter: document.getElementById("auditActionFilter"),
  auditLimitFilter: document.getElementById("auditLimitFilter"),
  auditTableBody: document.getElementById("auditTableBody"),
  auditCount: document.getElementById("auditCount"),
  securityFilterForm: document.getElementById("securityFilterForm"),
  securityTypeFilter: document.getElementById("securityTypeFilter"),
  securitySeverityFilter: document.getElementById("securitySeverityFilter"),
  securityUserFilter: document.getElementById("securityUserFilter"),
  securityLimitFilter: document.getElementById("securityLimitFilter"),
  securityTableBody: document.getElementById("securityTableBody"),
  securityCount: document.getElementById("securityCount"),
  demoTableBody: document.getElementById("demoTableBody"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value) {
  if (!value) {
    return "n/a";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function shortHash(value) {
  if (!value) {
    return "genesis";
  }

  return `${String(value).slice(0, 10)}...`;
}

function compactJson(value) {
  if (value === null || value === undefined || value === "") {
    return "n/a";
  }

  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value);
}

function prettyJson(value) {
  if (value === null || value === undefined || value === "") {
    return "n/a";
  }

  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value, null, 2);
}

function badge(value) {
  const label = String(value || "unknown");
  const kind = label.toLowerCase();
  return `<span class="badge ${escapeHtml(kind)}">${escapeHtml(label)}</span>`;
}

function requireSession() {
  if (!state.token) {
    setStatus("Sign in to load dashboard data", "error");
    return false;
  }

  return true;
}

function isAdmin() {
  return state.role === "admin";
}

function setStatus(message, kind = "normal") {
  elements.statusLine.textContent = message;
  elements.statusLine.classList.toggle("is-ok", kind === "ok");
  elements.statusLine.classList.toggle("is-error", kind === "error");
}

function setAuthState(message, kind = "normal") {
  elements.authState.textContent = message;
  elements.authState.classList.toggle("is-ok", kind === "ok");
  elements.authState.classList.toggle("is-error", kind === "error");
}

function authHeaders() {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${state.token}`,
  };
}

function jsonHeaders() {
  return {
    ...authHeaders(),
    "Content-Type": "application/json",
  };
}

async function parseResponse(response) {
  const data = await response.json().catch(async () => ({ detail: await response.text() }));

  if (!response.ok) {
    const detail = typeof data.detail === "string"
      ? data.detail
      : data.detail?.message || data.error || `HTTP ${response.status}`;
    const error = new Error(detail);
    error.status = response.status;
    error.payload = data;
    throw error;
  }

  return data;
}

async function getJson(path) {
  return parseResponse(await fetch(path, { headers: authHeaders() }));
}

async function postJson(path, body) {
  return parseResponse(await fetch(path, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify(body),
  }));
}

function saveSession(auth, username) {
  state.token = auth.access_token;
  state.role = auth.role;
  state.userId = auth.user_id;
  state.username = username;
  sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({
    access_token: state.token,
    role: state.role,
    user_id: state.userId,
    username,
  }));
  renderAuth();
}

function loadStoredSession() {
  const rawValue = sessionStorage.getItem(AUTH_STORAGE_KEY);
  if (!rawValue) {
    renderAuth();
    return;
  }

  try {
    const auth = JSON.parse(rawValue);
    state.token = auth.access_token || "";
    state.role = auth.role || "";
    state.userId = auth.user_id || "";
    state.username = auth.username || "";
  } catch {
    sessionStorage.removeItem(AUTH_STORAGE_KEY);
  }

  renderAuth();
}

function clearSession(message = "Signed out") {
  state.token = "";
  state.role = "";
  state.userId = "";
  state.username = "";
  state.contexts = [];
  state.selectedContextId = "";
  state.chain = [];
  state.audit = [];
  state.security = [];
  sessionStorage.removeItem(AUTH_STORAGE_KEY);
  elements.passwordInput.value = "";
  renderAuth();
  renderAll();
  setStatus(message);
}

function renderAuth() {
  const signedIn = Boolean(state.token);
  elements.loginForm.dataset.authMode = signedIn ? "signed-in" : "signed-out";
  elements.loginFields.hidden = signedIn;
  elements.loginFields.setAttribute("aria-hidden", signedIn ? "true" : "false");
  elements.loginButton.disabled = signedIn;
  elements.logoutButton.disabled = !signedIn;
  elements.usernameInput.disabled = signedIn;
  elements.passwordInput.disabled = signedIn;

  if (signedIn) {
    elements.passwordInput.value = "";
    setAuthState(`${state.username || state.userId} (${state.role})`, "ok");
  } else {
    setAuthState("Signed out");
  }
}

async function login(event) {
  event.preventDefault();
  const username = elements.usernameInput.value.trim();
  const password = elements.passwordInput.value;

  if (!username || !password) {
    setAuthState("Username and password required", "error");
    return;
  }

  elements.loginButton.disabled = true;
  setAuthState("Signing in...");

  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });
    const auth = await parseResponse(response);
    saveSession(auth, username);
    elements.passwordInput.value = "";
    setStatus("Signed in", "ok");
    await loadActiveView();
  } catch (error) {
    state.token = "";
    renderAuth();
    setAuthState(`Sign in failed: ${error.message}`, "error");
    setStatus("Authentication failed", "error");
  } finally {
    elements.loginButton.disabled = false;
    renderAuth();
  }
}

function setActiveView(viewName) {
  state.activeView = viewName;
  const view = views[viewName];
  elements.sectionTitle.textContent = view.title;
  elements.sectionKicker.textContent = view.kicker;

  elements.navButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === viewName);
  });
  elements.panels.forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.panel === viewName);
  });

  loadActiveView();
}

async function loadActiveView() {
  if (state.activeView === "demo") {
    renderDemo();
    return;
  }

  if (!requireSession()) {
    renderAll();
    return;
  }

  try {
    if (state.activeView === "contexts") {
      await loadContexts();
    } else if (state.activeView === "audit") {
      await loadAudit();
    } else if (state.activeView === "security") {
      await loadSecurityEvents();
    }
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      clearSession("Session expired or access denied");
      setAuthState("Session expired or access denied", "error");
      return;
    }

    setStatus(error.message, "error");
  }
}

function buildQuery(entries) {
  const params = new URLSearchParams();
  entries.forEach(([key, value]) => {
    const normalized = String(value ?? "").trim();
    if (normalized) {
      params.set(key, normalized);
    }
  });
  return params.toString();
}

async function createContext(event) {
  event.preventDefault();
  if (!requireSession()) {
    return;
  }

  const content = elements.contextContentInput.value.trim();
  if (!content) {
    elements.contextCreateState.textContent = "Content required";
    setStatus("Context content required", "error");
    return;
  }

  elements.contextCreateState.textContent = "Saving...";

  try {
    const body = {
      content,
      session_id: elements.contextSessionInput.value.trim() || null,
      context_type: elements.contextTypeInput.value.trim() || "general",
      priority: Number(elements.contextPriorityInput.value || 0),
    };
    const created = await postJson("/api/v1/contexts", body);
    elements.contextContentInput.value = "";
    state.selectedContextId = created.id;
    elements.contextCreateState.textContent = "Saved";
    setStatus("Context saved", "ok");
    await loadContexts();
  } catch (error) {
    const detected = error.payload?.detail?.detected_patterns;
    elements.contextCreateState.textContent = "Rejected";
    setStatus(detected ? `Rejected: ${compactJson(detected)}` : error.message, "error");
  }
}

async function loadContexts() {
  const query = buildQuery([
    ["session_id", elements.contextsSessionFilter.value],
    ["user_id", elements.contextsUserFilter.value],
    ["limit", elements.contextsLimitFilter.value || "50"],
  ]);
  state.contexts = await getJson(`/api/v1/contexts?${query}`);
  if (!state.selectedContextId && state.contexts.length > 0) {
    state.selectedContextId = state.contexts[0].id;
  }
  renderContexts();
  await loadSelectedContextChain();
  setStatus(`Contexts loaded: ${state.contexts.length}`, "ok");
}

function selectedContext() {
  return state.contexts.find((context) => context.id === state.selectedContextId) || null;
}

function renderContexts() {
  elements.contextsCount.textContent = `${state.contexts.length} rows`;

  if (state.contexts.length === 0) {
    elements.contextsTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No contexts</td></tr>`;
    state.selectedContextId = "";
  } else {
    elements.contextsTableBody.innerHTML = state.contexts.map((context) => `
      <tr data-context-id="${escapeHtml(context.id)}" class="${context.id === state.selectedContextId ? "is-selected" : ""}">
        <td>${escapeHtml(formatDate(context.created_at))}</td>
        <td>${escapeHtml(context.session_id || "none")}</td>
        <td>${badge(context.classification || "pending")}</td>
        <td>${escapeHtml(context.trust_score ?? "n/a")}</td>
        <td title="${escapeHtml(context.content_hash)}">${escapeHtml(shortHash(context.content_hash))}</td>
      </tr>
    `).join("");
  }

  renderContextDetails();
}

function renderContextDetails() {
  const context = selectedContext();
  elements.verifySelectedContextButton.disabled = !context;

  if (!context) {
    elements.contextDetails.innerHTML = `<div class="empty-state">No context selected</div>`;
    elements.chainTableBody.innerHTML = "";
    elements.chainState.textContent = "No context selected";
    return;
  }

  elements.contextDetails.innerHTML = `
    <div class="detail-cell">
      <span>ID</span>
      <strong>${escapeHtml(context.id)}</strong>
    </div>
    <div class="detail-cell">
      <span>User</span>
      <strong>${escapeHtml(context.user_id)}</strong>
    </div>
    <div class="detail-cell">
      <span>Session</span>
      <strong>${escapeHtml(context.session_id || "none")}</strong>
    </div>
    <div class="detail-cell">
      <span>Created</span>
      <strong>${escapeHtml(formatDate(context.created_at))}</strong>
    </div>
    <div class="detail-cell wide">
      <span>Content hash</span>
      <strong>${escapeHtml(context.content_hash)}</strong>
    </div>
    <div class="detail-cell wide">
      <span>Previous hash</span>
      <strong>${escapeHtml(context.previous_hash || "genesis")}</strong>
    </div>
    <div class="detail-cell full">
      <span>Content</span>
      <pre>${escapeHtml(context.content)}</pre>
    </div>
    <div class="detail-cell full">
      <span>Metadata</span>
      <pre>${escapeHtml(prettyJson(context.context_metadata || context.flags || {}))}</pre>
    </div>
  `;
}

async function loadSelectedContextChain() {
  const context = selectedContext();
  if (!context) {
    renderChain();
    return;
  }

  if (!context.session_id) {
    state.chain = [context];
    renderChain();
    return;
  }

  const query = buildQuery([
    ["session_id", context.session_id],
    ["user_id", isAdmin() ? context.user_id : ""],
    ["limit", "100"],
  ]);
  state.chain = await getJson(`/api/v1/contexts?${query}`);
  state.chain.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  renderChain();
}

function renderChain() {
  if (state.chain.length === 0) {
    elements.chainTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No chain records</td></tr>`;
    elements.chainState.textContent = "No chain";
    return;
  }

  elements.chainState.textContent = `${state.chain.length} records`;
  elements.chainTableBody.innerHTML = state.chain.map((context, index) => {
    const expectedPrevious = index === 0 ? null : state.chain[index - 1].content_hash;
    const matches = context.previous_hash === expectedPrevious;
    return `
      <tr class="${context.id === state.selectedContextId ? "is-selected" : ""}">
        <td>${index + 1}</td>
        <td>${escapeHtml(formatDate(context.created_at))}</td>
        <td title="${escapeHtml(context.content_hash)}">${escapeHtml(shortHash(context.content_hash))}</td>
        <td title="${escapeHtml(context.previous_hash || "genesis")}">${escapeHtml(shortHash(context.previous_hash))}</td>
        <td>${badge(matches ? "accept" : "reject")}</td>
      </tr>
    `;
  }).join("");
}

async function verifyContext(contextId, options = {}) {
  if (!requireSession()) {
    return;
  }

  const targetId = contextId || elements.verifyContextIdInput.value.trim();
  if (!targetId) {
    setStatus("Context ID required", "error");
    return;
  }

  elements.verificationState.textContent = "Running...";
  state.activeView = options.keepView ? state.activeView : "verification";

  try {
    state.verification = await postJson("/api/v1/contexts/verify", {
      context_id: targetId,
      check_tampering: elements.verifyTamperingInput.checked,
      check_replay: elements.verifyReplayInput.checked,
    });
    elements.verifyContextIdInput.value = targetId;
    elements.verificationState.textContent = "Complete";
    setStatus("Verification complete", "ok");
    if (!options.keepView && state.activeView !== "verification") {
      setActiveView("verification");
    }
    renderVerification();
  } catch (error) {
    elements.verificationState.textContent = "Failed";
    setStatus(error.message, "error");
  }
}

function renderVerification() {
  if (!state.verification) {
    elements.verificationResult.innerHTML = `<div class="empty-state">No verification result</div>`;
    return;
  }

  const result = state.verification;
  elements.verificationResult.innerHTML = `
    <div class="detail-cell">
      <span>Context</span>
      <strong>${escapeHtml(result.context_id)}</strong>
    </div>
    <div class="detail-cell">
      <span>Classification</span>
      <strong>${badge(result.classification)}</strong>
    </div>
    <div class="detail-cell">
      <span>Trust</span>
      <strong>${escapeHtml(result.trust_score)}</strong>
    </div>
    <div class="detail-cell">
      <span>Tampering</span>
      <strong>${escapeHtml(result.tampering_detected)}</strong>
    </div>
    <div class="detail-cell">
      <span>Replay</span>
      <strong>${escapeHtml(result.replay_attack_detected)}</strong>
    </div>
    <div class="detail-cell">
      <span>Valid</span>
      <strong>${escapeHtml(result.is_valid)}</strong>
    </div>
    <div class="detail-cell full">
      <span>Details</span>
      <pre>${escapeHtml(prettyJson(result.details))}</pre>
    </div>
  `;
}

async function verifyRagFile(event) {
  event.preventDefault();
  if (!requireSession()) {
    return;
  }

  const fileName = elements.ragFileNameInput.value.trim();
  const fileContent = elements.ragContentInput.value.trim();
  if (!fileName || !fileContent) {
    setStatus("File name and content required", "error");
    return;
  }

  elements.ragState.textContent = "Running...";

  try {
    state.rag = await postJson("/api/v1/rag/verify-file", {
      file_name: fileName,
      file_content: fileContent,
      data_source_id: elements.ragDataSourceInput.value.trim() || null,
    });
    elements.ragState.textContent = "Complete";
    renderRag();
    setStatus("RAG file verified", "ok");
  } catch (error) {
    elements.ragState.textContent = "Failed";
    setStatus(error.message, "error");
  }
}

function renderRag() {
  if (!state.rag) {
    elements.ragResult.innerHTML = `<div class="empty-state">No ingest result</div>`;
    return;
  }

  const result = state.rag;
  elements.ragResult.innerHTML = `
    <div class="detail-cell">
      <span>File</span>
      <strong>${escapeHtml(result.file_name)}</strong>
    </div>
    <div class="detail-cell">
      <span>Classification</span>
      <strong>${badge(result.classification)}</strong>
    </div>
    <div class="detail-cell">
      <span>Trust</span>
      <strong>${escapeHtml(result.trust_score)}</strong>
    </div>
    <div class="detail-cell full">
      <span>Content hash</span>
      <strong>${escapeHtml(result.content_hash)}</strong>
    </div>
    <div class="detail-cell full">
      <span>Details</span>
      <pre>${escapeHtml(prettyJson(result.verification_details))}</pre>
    </div>
  `;
}

async function loadAudit() {
  if (!isAdmin()) {
    elements.auditTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">Admin role required</td></tr>`;
    elements.auditCount.textContent = "0 rows";
    setStatus("Admin role required for audit", "error");
    return;
  }

  const query = buildQuery([
    ["user_id", elements.auditUserFilter.value],
    ["action", elements.auditActionFilter.value],
    ["limit", elements.auditLimitFilter.value || "50"],
  ]);
  state.audit = await getJson(`/api/v1/audit/history?${query}`);
  renderAudit();
  setStatus(`Audit loaded: ${state.audit.length}`, "ok");
}

function renderAudit() {
  elements.auditCount.textContent = `${state.audit.length} rows`;
  elements.auditTableBody.innerHTML = state.audit.length === 0
    ? `<tr><td colspan="5" class="empty-state">No audit rows</td></tr>`
    : state.audit.map((row) => `
      <tr>
        <td>${escapeHtml(formatDate(row.created_at))}</td>
        <td>${escapeHtml(row.user_id || "system")}</td>
        <td>${escapeHtml(row.action)}</td>
        <td>${escapeHtml(row.resource_type)} / ${escapeHtml(row.resource_id || "n/a")}</td>
        <td>${escapeHtml(compactJson(row.details))}</td>
      </tr>
    `).join("");
}

async function loadSecurityEvents() {
  if (!isAdmin()) {
    elements.securityTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">Admin role required</td></tr>`;
    elements.securityCount.textContent = "0 rows";
    setStatus("Admin role required for security events", "error");
    return;
  }

  const query = buildQuery([
    ["event_type", elements.securityTypeFilter.value],
    ["severity", elements.securitySeverityFilter.value],
    ["user_id", elements.securityUserFilter.value],
    ["limit", elements.securityLimitFilter.value || "50"],
  ]);
  state.security = await getJson(`/api/v1/security/events?${query}`);
  renderSecurityEvents();
  setStatus(`Security events loaded: ${state.security.length}`, "ok");
}

function renderSecurityEvents() {
  elements.securityCount.textContent = `${state.security.length} rows`;
  elements.securityTableBody.innerHTML = state.security.length === 0
    ? `<tr><td colspan="5" class="empty-state">No security events</td></tr>`
    : state.security.map((row) => `
      <tr>
        <td>${escapeHtml(formatDate(row.created_at))}</td>
        <td>${badge(row.severity)}</td>
        <td>${escapeHtml(row.event_type)}</td>
        <td>${escapeHtml(row.user_id || "system")}</td>
        <td>${escapeHtml(compactJson(row.details))}</td>
      </tr>
    `).join("");
}

function renderDemo() {
  elements.demoTableBody.innerHTML = demoPages.map((page) => `
    <tr>
      <td>${escapeHtml(page.title)}</td>
      <td>${escapeHtml(page.route)}</td>
      <td>${escapeHtml(page.status)}</td>
      <td><a href="${escapeHtml(page.route)}">Open</a></td>
    </tr>
  `).join("");
  if (state.activeView === "demo") {
    setStatus("Demo pages listed", "ok");
  }
}

function renderAll() {
  renderContexts();
  renderVerification();
  renderRag();
  renderAudit();
  renderSecurityEvents();
  renderDemo();
}

elements.navButtons.forEach((button) => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});
elements.loginForm.addEventListener("submit", login);
elements.logoutButton.addEventListener("click", () => clearSession());
elements.contextCreateForm.addEventListener("submit", createContext);
elements.contextsFilterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadContexts();
});
elements.contextsTableBody.addEventListener("click", (event) => {
  const row = event.target.closest("[data-context-id]");
  if (!row) {
    return;
  }
  state.selectedContextId = row.dataset.contextId;
  renderContexts();
  loadSelectedContextChain().catch((error) => setStatus(error.message, "error"));
});
elements.verifySelectedContextButton.addEventListener("click", () => {
  const context = selectedContext();
  if (context) {
    elements.verifyContextIdInput.value = context.id;
    verifyContext(context.id, { keepView: false });
  }
});
elements.verifyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  verifyContext();
});
elements.ragForm.addEventListener("submit", verifyRagFile);
elements.auditFilterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadAudit();
});
elements.securityFilterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadSecurityEvents();
});

loadStoredSession();
renderAll();
setActiveView("contexts");
