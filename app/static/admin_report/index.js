const tokenInput = document.getElementById("tokenInput");
const saveTokenButton = document.getElementById("saveTokenButton");
const clearTokenButton = document.getElementById("clearTokenButton");
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

const TOKEN_STORAGE_KEY = "civs_admin_jwt";

const state = {
  interactions: [],
  selectedId: null,
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

function getToken() {
  return tokenInput.value.trim();
}

function loadStoredToken() {
  tokenInput.value = localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function saveToken() {
  const token = getToken();

  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
    setStatus("Admin token сохранен", "ok");
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    setStatus("Токен очищен");
  }
}

function clearToken() {
  tokenInput.value = "";
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  state.interactions = [];
  state.selectedId = null;
  render();
  setStatus("Токен очищен");
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

async function loadInteractions() {
  const token = getToken();

  if (!token) {
    setStatus("Нужен admin JWT token", "error");
    render();
    return;
  }

  setStatus("Загрузка reports...");

  try {
    const response = await fetch(`/api/v1/admin/interactions?${buildQuery()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
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
        Reports не найдены или token не задан.
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

function render() {
  renderSummary();
  renderList();
  renderDetails();
}

saveTokenButton.addEventListener("click", () => {
  saveToken();
  loadInteractions();
});
clearTokenButton.addEventListener("click", clearToken);
refreshButton.addEventListener("click", loadInteractions);
projectFilter.addEventListener("change", loadInteractions);
blockedFilter.addEventListener("change", loadInteractions);
limitFilter.addEventListener("change", loadInteractions);

loadStoredToken();
render();

if (getToken()) {
  loadInteractions();
}
