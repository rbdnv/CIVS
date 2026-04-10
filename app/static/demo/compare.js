let state = null;

async function api(path, options = {}) {
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

function fillSafeExample() {
  if (!state) return;
  document.getElementById("contextInput").value = state.examples.safe_context;
}

function fillAttackExample() {
  if (!state) return;
  document.getElementById("contextInput").value = state.examples.malicious_context;
}

function setDefaultInputs() {
  if (!state) return;

  const contextInput = document.getElementById("contextInput");
  const questionInput = document.getElementById("questionInput");

  if (!contextInput.value.trim()) {
    contextInput.value = state.examples.safe_context;
  }

  if (!questionInput.value.trim()) {
    questionInput.value = state.examples.question;
  }
}

async function createSession() {
  state = await api("/api/v1/demo/session", { method: "POST" });
  setDefaultInputs();
  render();
}

async function resetDemo() {
  if (!state) return createSession();
  state = await api(`/api/v1/demo/session/${state.session_id}/reset`, { method: "POST" });
  document.getElementById("contextInput").value = state.examples.safe_context;
  document.getElementById("questionInput").value = state.examples.question;
  render();
}

async function submitMemory(content, label) {
  if (!state) {
    await createSession();
  }
  state = await api(`/api/v1/demo/session/${state.session_id}/memory`, {
    method: "POST",
    body: { content, label }
  });
  render();
}

async function submitCustomContext() {
  const content = document.getElementById("contextInput").value.trim();
  if (!content) return;
  await submitMemory(content, "Пользовательский контекст");
}

async function applyPresetSafe() {
  if (!state) {
    await createSession();
  }
  await submitMemory(state.examples.safe_context, "Безопасный контекст");
}

async function applyPresetAttack() {
  if (!state) {
    await createSession();
  }
  await submitMemory(state.examples.malicious_context, "Memory injection");
}

async function askQuestion() {
  if (!state) {
    await createSession();
  }
  const question = document.getElementById("questionInput").value.trim();
  if (!question) return;

  state = await api(`/api/v1/demo/session/${state.session_id}/query`, {
    method: "POST",
    body: { question }
  });
  render();
}

async function runFullDemo() {
  await resetDemo();
  await delay(180);
  await applyPresetSafe();
  await delay(180);
  await applyPresetAttack();
  await delay(180);
  await askQuestion();
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatPatterns(patterns) {
  const entries = Object.entries(patterns || {});
  if (!entries.length) {
    return '<div class="chip">Паттерны не обнаружены</div>';
  }

  return entries.map(([category, values]) => {
    const normalizedValues = Array.isArray(values) ? values.join(", ") : String(values);
    return `<div class="chip chip-danger">${escapeHtml(category)}: ${escapeHtml(normalizedValues)}</div>`;
  }).join("");
}

function renderOverview() {
  const gate = state.protected.last_gate;
  const overview = document.getElementById("overview");
  const leftStatus = state.vulnerable.compromised ? "Агент захвачен" : "Агент уязвим";
  const rightStatus = gate && !gate.accepted ? "Инъекция заблокирована" : "Защита активна";
  const trustScore = gate ? gate.trust_score : "—";

  overview.innerHTML = `
    <article class="metric">
      <span class="metric-label">Без CIVS</span>
      <div class="metric-value">${escapeHtml(leftStatus)}</div>
    </article>
    <article class="metric">
      <span class="metric-label">С CIVS</span>
      <div class="metric-value">${escapeHtml(rightStatus)}</div>
    </article>
    <article class="metric">
      <span class="metric-label">Последний Trust Score</span>
      <div class="metric-value">${trustScore === "—" ? trustScore : escapeHtml(String(trustScore))}</div>
    </article>
  `;
}

function renderMemory(items, emptyMessage) {
  if (!items.length) {
    return `<div class="empty">${escapeHtml(emptyMessage)}</div>`;
  }

  return items.slice().reverse().map((item) => `
    <article class="memory-item">
      <div class="memory-meta">
        <span>${escapeHtml(item.label)}</span>
        <span>${escapeHtml(item.created_at)}</span>
      </div>
      <div class="memory-title">${escapeHtml(item.classification || "CHECKED")}</div>
      <p class="memory-body">${escapeHtml(item.preview)}</p>
    </article>
  `).join("");
}

function renderLane(containerId, lane) {
  const isVulnerable = containerId === "vulnerableLane";
  const response = lane.last_response || (isVulnerable
    ? "Агент ещё не получил вопрос после изменения памяти."
    : "Пока что система только проверяла контекст.");

  const responseClass = response === "HACKED" ? "response-value response-hacked" : "response-value";
  const statusChip = isVulnerable
    ? (lane.compromised
        ? '<span class="chip chip-danger">Память отравлена</span>'
        : '<span class="chip chip-danger">Проверок нет</span>')
    : (lane.last_gate && lane.last_gate.accepted
        ? '<span class="chip chip-safe">Контекст допущен</span>'
        : '<span class="chip chip-safe">Защита активна</span>');

  const memoryHtml = renderMemory(
    lane.memory,
    isVulnerable
      ? "Пока в памяти нет записей. Добавь контекст или запусти полный сценарий."
      : "Память чистая. Опасный контекст сюда не попадёт."
  );

  const gate = !isVulnerable ? renderProtectedGate(state.protected.last_gate) : "";

  document.getElementById(containerId).innerHTML = `
    <div class="lane-header">
      <div>
        <h2 class="lane-title">${escapeHtml(lane.title)}</h2>
        <p class="lane-subtitle">
          ${isVulnerable
            ? "Любой payload сразу попадает в память. Если туда внедрить override-инструкцию, агент начнёт исполнять её."
            : "Каждый контекст проходит pre-check и финальную верификацию до записи в память."}
        </p>
      </div>
      <div class="stack">
        ${statusChip}
        <span class="chip">${lane.memory_count} записей в памяти</span>
      </div>
    </div>
    <div class="memory-list">${memoryHtml}</div>
    ${gate}
    <div class="response-box ${isVulnerable && lane.compromised ? "danger-glow" : ""} ${!isVulnerable && state.protected.last_gate && !state.protected.last_gate.accepted ? "safe-glow" : ""}">
      <span class="response-label">Последний ответ агента</span>
      <div class="${responseClass}">${escapeHtml(response)}</div>
    </div>
  `;
}

function renderProtectedGate(gate) {
  if (!gate) {
    return `
      <div class="response-box">
        <span class="response-label">Статус проверки CIVS</span>
        <div class="response-value">Защита готова. Отправь контекст, чтобы увидеть решение системы.</div>
      </div>
    `;
  }

  const details = gate.details || {};
  return `
    <div class="response-box">
      <span class="response-label">Последнее решение CIVS</span>
      <div class="stack" style="margin-bottom: 12px;">
        <span class="chip ${gate.accepted ? "chip-safe" : "chip-danger"}">${escapeHtml(gate.classification)}</span>
        <span class="chip">Trust Score: ${escapeHtml(String(gate.trust_score))}</span>
        <span class="chip">${escapeHtml(gate.stage)}</span>
      </div>
      <div class="memory-body" style="margin-bottom: 14px;">${escapeHtml(gate.message)}</div>
      <div class="stack" style="margin-bottom: 14px;">
        ${formatPatterns(gate.detected_patterns)}
      </div>
      <div class="steps">
        <div class="step">
          <h3>Signature / Hash Chain</h3>
          <p>signature_valid: <strong>${escapeHtml(String(details.signature_valid))}</strong>, hash_chain_valid: <strong>${escapeHtml(String(details.hash_chain_valid))}</strong></p>
        </div>
        <div class="step">
          <h3>Freshness / Replay</h3>
          <p>timestamp_fresh: <strong>${escapeHtml(String(details.timestamp_fresh))}</strong>, replay_attack_detected: <strong>${escapeHtml(String(details.replay_attack_detected))}</strong></p>
        </div>
      </div>
    </div>
  `;
}

function renderDetails() {
  const gate = state.protected.last_gate;
  const detailsGrid = document.getElementById("detailsGrid");
  const details = gate ? gate.details || {} : {};

  detailsGrid.innerHTML = `
    <article class="detail-card">
      <h3>1. Pre-check на suspicious content</h3>
      <p>${gate && !gate.accepted
        ? "Контекст остановлен ещё до записи в память, потому что найдены признаки prompt injection / memory poisoning."
        : "Если контент выглядит безопасным, он может перейти к криптографической верификации."}</p>
    </article>
    <article class="detail-card">
      <h3>2. Подпись Ed25519</h3>
      <p>Для безопасных контекстов создаётся цифровая подпись, чтобы дальше можно было проверить подлинность и неизменность данных.</p>
    </article>
    <article class="detail-card">
      <h3>3. Hash-chain и целостность</h3>
      <p>Hash-chain связывает контексты между собой. Сейчас hash_chain_valid = <strong>${escapeHtml(String(details.hash_chain_valid ?? "—"))}</strong>.</p>
    </article>
    <article class="detail-card">
      <h3>4. Trust Score и классификация</h3>
      <p>Финальное решение принимает verifier: Trust Score = <strong>${escapeHtml(String(gate ? gate.trust_score : "—"))}</strong>, classification = <strong>${escapeHtml(gate ? gate.classification : "—")}</strong>.</p>
    </article>
  `;
}

function renderEvents() {
  const container = document.getElementById("eventsList");
  if (!state.events.length) {
    container.innerHTML = '<div class="empty">Журнал появится после первых действий на странице.</div>';
    return;
  }

  container.innerHTML = state.events.map((event) => {
    const chipClass = event.status === "blocked"
      ? "chip-danger"
      : event.status === "danger"
        ? "chip-danger"
        : event.status === "accepted"
          ? "chip-safe"
          : "";

    const laneName = event.lane === "without_civs"
      ? "Без CIVS"
      : event.lane === "with_civs"
        ? "С CIVS"
        : "Система";

    return `
      <article class="event-item">
        <div class="event-meta">
          <span>${escapeHtml(laneName)}</span>
          <span>${escapeHtml(event.created_at)}</span>
        </div>
        <div class="event-title">${escapeHtml(event.title)}</div>
        <p class="event-body">${escapeHtml(event.message)}</p>
        <div class="stack" style="margin-top: 12px;">
          <span class="chip ${chipClass}">${escapeHtml(event.status)}</span>
        </div>
      </article>
    `;
  }).join("");
}

function render() {
  if (!state) return;
  renderOverview();
  renderLane("vulnerableLane", state.vulnerable);
  renderLane("protectedLane", state.protected);
  renderDetails();
  renderEvents();
}

window.addEventListener("load", async () => {
  try {
    await createSession();
  } catch (error) {
    document.body.innerHTML = `<div class="shell"><section class="panel"><h1 style="font-size:2rem;">Не удалось загрузить demo</h1><p class="hero-copy">${escapeHtml(error.message)}</p></section></div>`;
  }
});
