const loginForm = document.getElementById("loginForm");
const usernameInput = document.getElementById("usernameInput");
const passwordInput = document.getElementById("passwordInput");
const loginButton = document.getElementById("loginButton");
const logoutButton = document.getElementById("logoutButton");
const authState = document.getElementById("authState");
const refreshButton = document.getElementById("refreshButton");
const projectFilter = document.getElementById("projectFilter");
const blockedFilter = document.getElementById("blockedFilter");
const limitFilter = document.getElementById("limitFilter");
const statusText = document.getElementById("statusText");
const summary = document.getElementById("summary");
const totalCount = document.getElementById("totalCount");
const interactionList = document.getElementById("interactionList");
const interactionDetails = document.getElementById("interactionDetails");
const selectedState = document.getElementById("selectedState");

const AUTH_STORAGE_KEY = "civs_admin_auth";

const state = {
  interactions: [],
  selectedId: null,
  token: "",
  username: "",
  role: "",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setStatus(message, kind = "normal") {
  statusText.textContent = message;
  statusText.classList.toggle("is-ok", kind === "ok");
  statusText.classList.toggle("is-error", kind === "error");
}

function setAuthState(message, kind = "normal") {
  authState.textContent = message;
  authState.classList.toggle("is-ok", kind === "ok");
  authState.classList.toggle("is-error", kind === "error");
}

function hasAdminSession() {
  return Boolean(state.token && state.role === "admin");
}

function saveSession(auth) {
  state.token = auth.access_token;
  state.username = auth.username;
  state.role = auth.role;
  sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
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
    state.username = auth.username || "";
    state.role = auth.role || "";
  } catch {
    sessionStorage.removeItem(AUTH_STORAGE_KEY);
  }

  renderAuth();
}

function clearSession(message = "Вход сброшен") {
  state.token = "";
  state.username = "";
  state.role = "";
  usernameInput.value = "";
  passwordInput.value = "";
  sessionStorage.removeItem(AUTH_STORAGE_KEY);
  state.interactions = [];
  state.selectedId = null;
  renderAuth();
  render();
  setStatus(message);
}

function buildQuery() {
  const params = new URLSearchParams();
  const projectName = projectFilter.value.trim();
  const blocked = blockedFilter.value;
  const limit = limitFilter.value || "100";

  if (projectName) {
    params.set("project_name", projectName);
  }

  if (blocked) {
    params.set("blocked", blocked);
  }

  params.set("limit", limit);
  return params.toString();
}

async function login(event) {
  event.preventDefault();

  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    setAuthState("Введите username и password", "error");
    return;
  }

  loginButton.disabled = true;
  setAuthState("Проверка доступа...");

  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.detail || `HTTP ${response.status}`);
    }

    if (data.role !== "admin") {
      throw new Error("Нужна роль admin");
    }

    saveSession({
      access_token: data.access_token,
      role: data.role,
      user_id: data.user_id,
      username,
    });
    passwordInput.value = "";
    setStatus("Admin-вход выполнен", "ok");
    await loadInteractions();
  } catch (error) {
    clearSession("Вход не выполнен");
    usernameInput.value = username;
    setAuthState(`Ошибка входа: ${error.message}`, "error");
    setStatus("Admin-вход не выполнен", "error");
  } finally {
    loginButton.disabled = false;
  }
}

async function loadInteractions() {
  if (!hasAdminSession()) {
    setStatus("Нужен вход admin-пользователя", "error");
    render();
    return;
  }

  setStatus("Загрузка reports...");

  try {
    const response = await fetch(`/api/v1/admin/interactions?${buildQuery()}`, {
      headers: {
        Authorization: `Bearer ${state.token}`,
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText.slice(0, 240)}`);
    }

    state.interactions = await response.json();
    state.selectedId = state.interactions[0]?.id || null;
    render();
    setStatus(`Загружено: ${state.interactions.length}`, "ok");
  } catch (error) {
    if (String(error.message).includes("HTTP 401") || String(error.message).includes("HTTP 403")) {
      clearSession("Сессия истекла или нет admin-доступа");
      setAuthState("Сессия истекла или нет admin-доступа", "error");
      return;
    }

    state.interactions = [];
    state.selectedId = null;
    render();
    setStatus(`Ошибка загрузки: ${error.message}`, "error");
  }
}

function verdictClass(verdict) {
  const normalized = String(verdict || "").toLowerCase();

  if (normalized === "accept") {
    return "accept";
  }

  if (normalized === "reject") {
    return "reject";
  }

  return "quarantine";
}

function formatDate(value) {
  if (!value) {
    return "не завершено";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("ru-RU");
}

function formatTrust(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(3) : "n/a";
}

function getProfileData(interaction) {
  const profile = interaction.profile_snapshot || {};
  const data = profile.data && typeof profile.data === "object" ? profile.data : {};
  const interests = data.interests ?? profile.interests ?? [];

  return {
    login: profile.login || interaction.external_user_id || "unknown",
    name: profile.name || interaction.external_username || "unknown",
    goal: data.goal ?? profile.goal ?? "",
    interests: Array.isArray(interests) ? interests.join(", ") : String(interests || ""),
  };
}

function collectPatterns(checks) {
  const patterns = [];

  for (const check of checks || []) {
    const suspiciousPatterns = check.suspicious_patterns || {};

    for (const [category, matches] of Object.entries(suspiciousPatterns)) {
      const list = Array.isArray(matches) ? matches : [matches];
      patterns.push({
        label: check.label,
        category,
        matches: list.map((item) => String(item)),
      });
    }
  }

  return patterns;
}

function renderSummary() {
  const total = state.interactions.length;
  const blocked = state.interactions.filter((item) => item.blocked).length;
  const allowed = total - blocked;
  const completed = state.interactions.filter((item) => item.completed_at).length;

  summary.innerHTML = [
    ["Всего", total],
    ["Allowed", allowed],
    ["Blocked", blocked],
    ["Completed", completed],
  ]
    .map(
      ([label, value]) => `
        <article class="summary-card">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </article>
      `,
    )
    .join("");
}

function renderList() {
  totalCount.textContent = String(state.interactions.length);

  if (!state.interactions.length) {
    interactionList.innerHTML = `
      <div class="details-empty">
        Reports не найдены или admin-вход не выполнен.
      </div>
    `;
    return;
  }

  interactionList.innerHTML = state.interactions
    .map((interaction) => {
      const profile = getProfileData(interaction);
      const selected = interaction.id === state.selectedId ? " is-selected" : "";
      const stateLabel = interaction.blocked ? "blocked" : "allowed";

      return `
        <button class="interaction-item${selected}" data-id="${escapeHtml(interaction.id)}" type="button">
          <div class="interaction-title">
            <span>${escapeHtml(profile.login)}</span>
            <span class="pill ${verdictClass(interaction.verdict)}">${escapeHtml(interaction.verdict)}</span>
          </div>
          <div class="interaction-meta">${escapeHtml(formatDate(interaction.created_at))}</div>
          <div>${escapeHtml(interaction.request_text).slice(0, 180)}</div>
          <div class="pill-row">
            <span class="pill">${escapeHtml(interaction.project_name)}</span>
            <span class="pill">${escapeHtml(stateLabel)}</span>
            <span class="pill">trust ${escapeHtml(formatTrust(interaction.trust_score))}</span>
          </div>
        </button>
      `;
    })
    .join("");

  for (const button of interactionList.querySelectorAll(".interaction-item")) {
    button.addEventListener("click", () => {
      state.selectedId = button.dataset.id;
      render();
    });
  }
}

function renderDetails() {
  const interaction = state.interactions.find((item) => item.id === state.selectedId);

  if (!interaction) {
    selectedState.textContent = "Не выбран";
    interactionDetails.className = "details-empty";
    interactionDetails.textContent = "Выберите запись из истории.";
    return;
  }

  const profile = getProfileData(interaction);
  const patterns = collectPatterns(interaction.checks);
  const stateLabel = interaction.blocked ? "Blocked" : "Allowed";
  selectedState.textContent = stateLabel;
  interactionDetails.className = "details-body";
  interactionDetails.innerHTML = `
    <div class="pill-row">
      <span class="pill ${verdictClass(interaction.verdict)}">${escapeHtml(interaction.verdict)}</span>
      <span class="pill">${escapeHtml(stateLabel)}</span>
      <span class="pill">trust ${escapeHtml(formatTrust(interaction.trust_score))}</span>
      <span class="pill">${escapeHtml(interaction.classification)}</span>
    </div>

    <div class="detail-grid">
      ${detailBox("Project", interaction.project_name)}
      ${detailBox("User", `${profile.login} / ${profile.name}`)}
      ${detailBox("Session ID", interaction.session_id || "не указан")}
      ${detailBox("Created", formatDate(interaction.created_at))}
      ${detailBox("Completed", formatDate(interaction.completed_at))}
      ${detailBox("Tool action", interaction.tool_action || "не указан")}
      ${detailBox("Profile goal", profile.goal || "не указан", true)}
      ${detailBox("Profile interests", profile.interests || "не указаны", true)}
      ${detailBox("Question", interaction.request_text, true)}
      ${detailBox("Model response", interaction.response_text || "ответ еще не сохранен", true)}
      ${detailBox("Error", interaction.error || "нет", true)}
    </div>

    <section>
      <h3>Detected patterns</h3>
      ${renderPatterns(patterns)}
    </section>

    <section>
      <h3>Checks</h3>
      ${renderChecks(interaction.checks || [])}
    </section>

    <section>
      <h3>Profile snapshot</h3>
      <pre>${escapeHtml(JSON.stringify(interaction.profile_snapshot || {}, null, 2))}</pre>
    </section>
  `;
}

function detailBox(label, value, full = false) {
  return `
    <div class="detail-box${full ? " full" : ""}">
      <div class="detail-label">${escapeHtml(label)}</div>
      <div class="detail-value">${escapeHtml(value)}</div>
    </div>
  `;
}

function renderPatterns(patterns) {
  if (!patterns.length) {
    return `<p class="muted">Подозрительные паттерны не найдены.</p>`;
  }

  return `
    <div class="pill-row">
      ${patterns
        .map(
          (pattern) => `
            <span class="pill reject">
              ${escapeHtml(pattern.label)} / ${escapeHtml(pattern.category)}:
              ${escapeHtml(pattern.matches.join(", "))}
            </span>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderChecks(checks) {
  if (!checks.length) {
    return `<p class="muted">Checks отсутствуют.</p>`;
  }

  return `
    <table class="checks-table">
      <thead>
        <tr>
          <th>Label</th>
          <th>Verdict</th>
          <th>Trust</th>
          <th>Patterns</th>
        </tr>
      </thead>
      <tbody>
        ${checks
          .map((check) => {
            const patterns = collectPatterns([check])
              .map((item) => `${item.category}: ${item.matches.join(", ")}`)
              .join("\n");

            return `
              <tr>
                <td>${escapeHtml(check.label)}</td>
                <td>${escapeHtml(check.classification)}</td>
                <td>${escapeHtml(formatTrust(check.trust_score))}</td>
                <td>${escapeHtml(patterns || "none")}</td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

function renderAuth() {
  const isAdmin = hasAdminSession();
  usernameInput.disabled = isAdmin;
  passwordInput.disabled = isAdmin;
  loginButton.disabled = isAdmin;
  logoutButton.disabled = !isAdmin;

  if (isAdmin) {
    usernameInput.value = state.username;
    setAuthState(`Admin: ${state.username}`, "ok");
  } else {
    setAuthState("Не выполнен вход");
  }
}

function render() {
  renderAuth();
  renderSummary();
  renderList();
  renderDetails();
}

loginForm.addEventListener("submit", login);
logoutButton.addEventListener("click", () => clearSession());
refreshButton.addEventListener("click", loadInteractions);
projectFilter.addEventListener("change", loadInteractions);
blockedFilter.addEventListener("change", loadInteractions);
limitFilter.addEventListener("change", loadInteractions);

loadStoredSession();
render();

if (hasAdminSession()) {
  loadInteractions();
}
