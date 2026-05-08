let playgroundState = null;
let playgroundStatus = null;

async function playgroundApi(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = await response.json();
      detail = payload.detail || payload.message || JSON.stringify(payload);
    } catch (error) {
      detail = response.statusText;
    }
    throw new Error(detail);
  }

  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatPatterns(patterns) {
  const entries = Object.entries(patterns || {});
  if (!entries.length) {
    return '<span class="chip chip-safe">Паттерны не обнаружены</span>';
  }

  return entries.map(([category, values]) => {
    const normalized = Array.isArray(values) ? values.join(", ") : String(values);
    return `<span class="chip chip-danger">${escapeHtml(category)}: ${escapeHtml(normalized)}</span>`;
  }).join("");
}

async function fetchPlaygroundStatus() {
  playgroundStatus = await playgroundApi("/api/v1/demoapp/status");
  renderStatus();
}

async function createPlaygroundSession() {
  playgroundState = await playgroundApi("/api/v1/demoapp/session", { method: "POST" });
  setFormFromSession();
  renderPlayground();
}

async function ensurePlaygroundSession() {
  if (!playgroundStatus) {
    await fetchPlaygroundStatus();
  }
  if (!playgroundState) {
    await createPlaygroundSession();
  }
}

function setFormFromSession() {
  if (!playgroundState) return;

  const profile = playgroundState.profile;
  document.getElementById("nameInput").value = profile.name || "";
  document.getElementById("ageInput").value = profile.age || "";
  document.getElementById("goalInput").value = profile.goal || "";
  document.getElementById("interestsInput").value = (profile.interests || []).join(", ");
  document.getElementById("questionInput").value = playgroundState.last_question || playgroundState.examples.question;
}

function buildProfilePayload() {
  return {
    name: document.getElementById("nameInput").value.trim(),
    age: document.getElementById("ageInput").value.trim(),
    goal: document.getElementById("goalInput").value.trim(),
    interests: document.getElementById("interestsInput").value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
  };
}

async function saveProfile() {
  await ensurePlaygroundSession();
  playgroundState = await playgroundApi(`/api/v1/demoapp/session/${playgroundState.session_id}/profile`, {
    method: "POST",
    body: buildProfilePayload()
  });
  renderPlayground();
}

async function resetPlayground() {
  await ensurePlaygroundSession();
  playgroundState = await playgroundApi(`/api/v1/demoapp/session/${playgroundState.session_id}/reset`, {
    method: "POST"
  });
  setFormFromSession();
  renderPlayground();
}

async function runCompare() {
  await saveProfile();
  const question = document.getElementById("questionInput").value.trim();
  if (!question) return;

  playgroundState = await playgroundApi(`/api/v1/demoapp/session/${playgroundState.session_id}/query`, {
    method: "POST",
    body: { question }
  });
  renderPlayground();
}

function applySafeProfile() {
  if (!playgroundState) return;
  document.getElementById("goalInput").value = playgroundState.examples.safe_goal;
  document.getElementById("interestsInput").value = playgroundState.examples.safe_interests.join(", ");
}

function applyAttackProfileRu() {
  if (!playgroundState) return;
  document.getElementById("goalInput").value = playgroundState.examples.malicious_goal_ru;
  document.getElementById("interestsInput").value = "python, ai, prompt injection";
}

function applyAttackProfileEn() {
  if (!playgroundState) return;
  document.getElementById("goalInput").value = playgroundState.examples.malicious_goal_en;
  document.getElementById("interestsInput").value = "python, ai, prompt injection";
}

function applySafeQuestion() {
  if (!playgroundState) return;
  document.getElementById("questionInput").value = playgroundState.examples.question;
}

function applyAttackQuestion() {
  if (!playgroundState) return;
  document.getElementById("questionInput").value = playgroundState.examples.malicious_question;
}

async function runSafeScenario() {
  await ensurePlaygroundSession();
  setFormFromSession();
  applySafeProfile();
  applySafeQuestion();
  await runCompare();
}

async function runAttackScenarioRu() {
  await ensurePlaygroundSession();
  applyAttackProfileRu();
  applySafeQuestion();
  await runCompare();
}

async function runAttackScenarioEn() {
  await ensurePlaygroundSession();
  applyAttackProfileEn();
  applySafeQuestion();
  await runCompare();
}

function renderStatus(overrideMessage = null) {
  const banner = document.getElementById("statusBanner");
  const providerStrip = document.getElementById("providerStrip");
  const note = document.getElementById("playgroundNote");
  const enabled = Boolean(playgroundStatus?.enabled);
  const provider = playgroundStatus?.provider || "unknown";
  const model = playgroundStatus?.model || "unknown";
  const endpoint = playgroundStatus?.endpoint || "unknown";

  banner.className = `status-banner ${enabled ? "live-ready" : "live-missing"}`;
  banner.innerHTML = `
    <div class="status-grid">
      <span class="chip ${enabled ? "chip-safe" : "chip-danger"}">${enabled ? "Ollama ready" : "Ollama unavailable"}</span>
      <span class="chip">Provider: ${escapeHtml(provider)}</span>
      <span class="chip">Model: ${escapeHtml(model)}</span>
      <span class="chip">Endpoint: ${escapeHtml(endpoint)}</span>
    </div>
    <div>${escapeHtml(overrideMessage || playgroundStatus?.message || "")}</div>
  `;

  providerStrip.innerHTML = `
    <article class="provider-card provider-demoapp">
      <div class="provider-topline">
        <span class="provider-label">demoapp Provider</span>
        <span class="provider-ready ${enabled ? "is-ready" : "not-ready"}">${enabled ? "Ready" : "Not ready"}</span>
      </div>
      <div class="provider-value">${escapeHtml(provider)}</div>
      <div class="provider-meta">Model: ${escapeHtml(model)}</div>
      <div class="provider-meta">Endpoint: ${escapeHtml(endpoint)}</div>
    </article>
  `;

  note.textContent = enabled
    ? "Playground обращается к той же локальной Ollama-модели, что и demoapp. Разница только в наличии CIVS-проверки перед запросом."
    : "Сначала запустите локальный Ollama, иначе compare-режим не сможет обратиться к реальной модели.";
}

function renderOverview() {
  if (!playgroundState) return;

  const profileSafe = playgroundState.summary.profile_safe;
  const attackBlocked = playgroundState.summary.attack_blocked;
  const lastGate = playgroundState.protected.last_gate;

  document.getElementById("overview").innerHTML = `
    <article class="metric">
      <span class="metric-label">Profile context</span>
      <div class="metric-value">${profileSafe ? "Safe" : "Suspicious"}</div>
    </article>
    <article class="metric">
      <span class="metric-label">Protected lane</span>
      <div class="metric-value">${attackBlocked ? "Blocked before LLM" : "Reached Ollama"}</div>
    </article>
    <article class="metric">
      <span class="metric-label">Last trust score</span>
      <div class="metric-value">${lastGate ? escapeHtml(String(lastGate.trust_score)) : "—"}</div>
    </article>
  `;
}

function renderProfileReport() {
  const container = document.getElementById("profileReport");
  const report = playgroundState.profile.profile_report;
  const checks = report.checks || [];

  container.innerHTML = `
    <article class="profile-verdict ${report.accepted ? "is-safe" : "is-blocked"}">
      <strong>${report.accepted ? "Профиль проходит CIVS-проверку" : "Профиль выглядит как memory/profile injection"}</strong>
      <div class="mini-copy">${escapeHtml(report.message)}</div>
    </article>
    <div class="trace-list">
      ${checks.map((item) => `
        <div class="trace-item">
          <strong>${escapeHtml(item.label)}</strong>
          <div class="mini-copy">${escapeHtml(item.message)}</div>
          <div class="chip-row">${formatPatterns(item.suspicious_patterns)}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderLaneResults() {
  const vulnerable = playgroundState.vulnerable;
  const protectedLane = playgroundState.protected;
  const guard = protectedLane.last_gate;

  document.getElementById("vulnerableLane").innerHTML = `
    <div class="lane-header">
      <div>
        <span class="lane-badge lane-badge-danger">Уязвимый prompt builder</span>
        <h2 class="lane-title">${escapeHtml(vulnerable.title)}</h2>
        <p class="lane-subtitle">Профиль пользователя напрямую попадает в prompt без проверки.</p>
      </div>
    </div>
    <div class="result-box">
      <pre>${escapeHtml(vulnerable.last_response || "Пока нет ответа. Сначала задайте вопрос.")}</pre>
    </div>
  `;

  document.getElementById("protectedLane").innerHTML = `
    <div class="lane-header">
      <div>
        <span class="lane-badge lane-badge-safe">CIVS guard layer</span>
        <h2 class="lane-title">${escapeHtml(protectedLane.title)}</h2>
        <p class="lane-subtitle">Перед отправкой в Ollama CIVS проверяет profile context и сам вопрос.</p>
      </div>
    </div>
    <div class="result-box">
      <pre>${escapeHtml(protectedLane.last_response || "Пока нет ответа. Сначала задайте вопрос.")}</pre>
    </div>
    <div class="trace-list">
      <div class="trace-item">
        <strong>Последний gate verdict</strong>
        <div class="mini-copy">${escapeHtml(guard?.message || "Ветка ещё не выполнялась.")}</div>
        <div class="chip-row">${guard ? formatPatterns(guard.blocked_checks?.reduce((acc, item) => {
          Object.entries(item.suspicious_patterns || {}).forEach(([key, values]) => {
            acc[key] = (acc[key] || []).concat(values);
          });
          return acc;
        }, {}) || {}) : '<span class="chip">Нет данных</span>'}</div>
      </div>
    </div>
  `;
}

function renderEvents() {
  const container = document.getElementById("eventsList");
  const events = playgroundState.events || [];

  if (!events.length) {
    container.innerHTML = '<div class="empty">Событий пока нет.</div>';
    return;
  }

  container.innerHTML = events.slice().reverse().map((event) => `
    <article class="event-item event-${escapeHtml(event.status)}">
      <div class="event-head">
        <span class="chip">${escapeHtml(event.lane)}</span>
        <span>${escapeHtml(event.created_at)}</span>
      </div>
      <h3>${escapeHtml(event.title)}</h3>
      <p>${escapeHtml(event.message)}</p>
    </article>
  `).join("");
}

function renderBlockedAttempts() {
  const container = document.getElementById("blockedAttemptsList");
  const attempts = playgroundState.blocked_attempts || [];

  if (!attempts.length) {
    container.innerHTML = '<div class="empty">Пока ни один опасный payload не был остановлен.</div>';
    return;
  }

  container.innerHTML = attempts.slice().reverse().map((attempt) => `
    <div class="trace-item trace-danger">
      <strong>${escapeHtml(attempt.source)}</strong>
      <div class="mini-copy">${escapeHtml(attempt.message)}</div>
      <div class="chip-row">${formatPatterns(attempt.suspicious_patterns)}</div>
      <div class="payload-box">${escapeHtml(attempt.payload || "[empty]")}</div>
      <div class="mini-copy">${escapeHtml(attempt.created_at)}</div>
    </div>
  `).join("");
}

function renderDetails() {
  const report = playgroundState.profile.profile_report;
  const lastGate = playgroundState.protected.last_gate;
  const profileGoal = playgroundState.profile.goal;
  const lastQuestion = playgroundState.last_question || playgroundState.examples.question;

  document.getElementById("detailsGrid").innerHTML = `
    <article class="detail-card">
      <span class="detail-label">1. Attack surface</span>
      <div class="detail-title">demoapp хранит prompt-sensitive profile context</div>
      <p class="detail-copy">Поле <code>goal</code> подмешивается в prompt на каждом запросе, поэтому оно работает как persistent memory.</p>
    </article>
    <article class="detail-card">
      <span class="detail-label">2. Current profile.goal</span>
      <div class="detail-title">${escapeHtml(profileGoal)}</div>
      <p class="detail-copy">${escapeHtml(report.message)}</p>
    </article>
    <article class="detail-card">
      <span class="detail-label">3. Current question</span>
      <div class="detail-title">${escapeHtml(lastQuestion)}</div>
      <p class="detail-copy">${escapeHtml(lastGate?.message || "После выполнения сравнения здесь появится verdict protected lane.")}</p>
    </article>
  `;
}

function renderPlayground() {
  renderStatus();
  renderOverview();
  renderProfileReport();
  renderLaneResults();
  renderEvents();
  renderBlockedAttempts();
  renderDetails();
}

async function bootstrapPlayground() {
  try {
    await fetchPlaygroundStatus();
    await createPlaygroundSession();
  } catch (error) {
    renderStatus(error.message);
  }
}

bootstrapPlayground();
