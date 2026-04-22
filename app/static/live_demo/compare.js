let liveState = null;
let liveStatus = null;

async function liveApi(path, options = {}) {
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

function formatUsage(usage) {
  if (!usage || Object.keys(usage).length === 0) {
    return '<span class="chip">usage: n/a</span>';
  }

  return Object.entries(usage)
    .filter(([, value]) => typeof value === "number")
    .map(([key, value]) => `<span class="chip">${escapeHtml(key)}: ${escapeHtml(String(value))}</span>`)
    .join("");
}

async function fetchLiveStatus() {
  liveStatus = await liveApi("/api/v1/live-demo/status");
  renderStatus();
}

async function createLiveSession() {
  liveState = await liveApi("/api/v1/live-demo/session", { method: "POST" });
  setDefaultInputs();
  renderLive();
}

async function ensureLiveSession() {
  if (!liveStatus) {
    await fetchLiveStatus();
  }
  if (!liveState) {
    await createLiveSession();
  }
}

function setDefaultInputs() {
  if (!liveState) return;

  const contextInput = document.getElementById("contextInput");
  const questionInput = document.getElementById("questionInput");

  if (!contextInput.value.trim()) {
    contextInput.value = liveState.examples.safe_context;
  }

  if (!questionInput.value.trim()) {
    questionInput.value = liveState.examples.question;
  }
}

function fillLiveSafeExample() {
  if (!liveState) return;
  document.getElementById("contextInput").value = liveState.examples.safe_context;
}

function fillLiveAttackExample() {
  if (!liveState) return;
  document.getElementById("contextInput").value = liveState.examples.malicious_context;
}

async function resetLiveDemo() {
  await ensureLiveSession();
  liveState = await liveApi(`/api/v1/live-demo/session/${liveState.session_id}/reset`, { method: "POST" });
  document.getElementById("contextInput").value = liveState.examples.safe_context;
  document.getElementById("questionInput").value = liveState.examples.question;
  renderLive();
}

async function submitLiveMemory(content, label) {
  await ensureLiveSession();
  liveState = await liveApi(`/api/v1/live-demo/session/${liveState.session_id}/memory`, {
    method: "POST",
    body: { content, label }
  });
  renderLive();
}

async function submitLiveContext() {
  const content = document.getElementById("contextInput").value.trim();
  if (!content) return;
  await submitLiveMemory(content, "Пользовательский context");
}

async function applyLiveSafe() {
  await ensureLiveSession();
  await submitLiveMemory(liveState.examples.safe_context, "Безопасный memory chunk");
}

async function applyLiveAttack() {
  await ensureLiveSession();
  await submitLiveMemory(liveState.examples.malicious_context, "Memory injection");
}

async function askLiveQuestion() {
  await ensureLiveSession();
  if (!liveStatus?.enabled) {
    renderStatus("Для live demo сначала добавь OPENAI_API_KEY в .env.");
    return;
  }

  const question = document.getElementById("questionInput").value.trim();
  if (!question) return;

  liveState = await liveApi(`/api/v1/live-demo/session/${liveState.session_id}/query`, {
    method: "POST",
    body: { question }
  });
  renderLive();
}

async function runFullLiveDemo() {
  await resetLiveDemo();
  await delay(180);
  await applyLiveSafe();
  await delay(180);
  await applyLiveAttack();
  await delay(180);
  await askLiveQuestion();
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function renderStatus(overrideMessage = null) {
  const banner = document.getElementById("statusBanner");
  const enabled = Boolean(liveStatus?.enabled);
  banner.className = `status-banner ${enabled ? "live-ready" : "live-missing"}`;
  banner.innerHTML = `
    <div class="status-grid">
      <span class="chip ${enabled ? "chip-safe" : "chip-danger"}">${enabled ? "Live mode enabled" : "Live mode disabled"}</span>
      <span class="chip">Provider: ${escapeHtml(liveStatus?.provider || "unknown")}</span>
      <span class="chip">Model: ${escapeHtml(liveStatus?.model || "unknown")}</span>
    </div>
    <div>${escapeHtml(overrideMessage || liveStatus?.message || "")}</div>
  `;
}

function renderOverview() {
  const gate = liveState.protected.last_gate;
  const leftStatus = liveState.vulnerable.compromised ? "Реальный агент захвачен" : "Память без фильтра";
  const rightStatus = gate && !gate.accepted ? "Инъекция заблокирована CIVS" : "Проверки активны";
  const trustScore = gate ? gate.trust_score : "—";

  document.getElementById("overview").innerHTML = `
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

function renderLLMBox(metadata) {
  if (!metadata) {
    return `
      <div class="llm-box">
        <h3>LLM call metadata</h3>
        <div class="memory-body">Запрос к модели ещё не выполнялся.</div>
      </div>
    `;
  }

  return `
    <div class="llm-box">
      <h3>LLM call metadata</h3>
      <div class="llm-meta">
        <span class="chip">model: ${escapeHtml(metadata.model || "n/a")}</span>
        <span class="chip">response_id: ${escapeHtml((metadata.response_id || "n/a").slice(0, 18))}</span>
        <span class="chip">latency: ${escapeHtml(String(metadata.latency_ms || "n/a"))} ms</span>
        ${formatUsage(metadata.usage)}
      </div>
    </div>
  `;
}

function renderProtectedGate(gate) {
  if (!gate) {
    return `
      <div class="response-box">
        <span class="response-label">Статус проверки CIVS</span>
        <div class="response-value">Отправь контекст, чтобы увидеть, пропустит ли его CIVS к реальному агенту.</div>
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
          <h3>Timestamp / Replay</h3>
          <p>timestamp_fresh: <strong>${escapeHtml(String(details.timestamp_fresh))}</strong>, replay_attack_detected: <strong>${escapeHtml(String(details.replay_attack_detected))}</strong></p>
        </div>
      </div>
    </div>
  `;
}

function renderLane(containerId, lane, llmMeta) {
  const isVulnerable = containerId === "vulnerableLane";
  const response = lane.last_response || (isVulnerable
    ? "Модель ещё не получила вопрос после изменения памяти."
    : "Пока что CIVS только проверял контекст до вызова модели.");

  const responseClass = response.trim() === "HACKED" ? "response-value response-hacked" : "response-value";
  const statusChip = isVulnerable
    ? (lane.compromised
        ? '<span class="chip chip-danger">Модель подхватила инъекцию</span>'
        : '<span class="chip chip-danger">Память без фильтра</span>')
    : (lane.last_gate && lane.last_gate.accepted
        ? '<span class="chip chip-safe">Контекст допущен к LLM</span>'
        : '<span class="chip chip-safe">CIVS перед моделью</span>');

  const memoryHtml = renderMemory(
    lane.memory,
    isVulnerable
      ? "Пока в памяти нет записей. Добавь контекст или запусти полный live-сценарий."
      : "Память чистая. Подозрительные контексты сюда не попадают."
  );

  const gate = !isVulnerable ? renderProtectedGate(liveState.protected.last_gate) : "";

  document.getElementById(containerId).innerHTML = `
    <div class="lane-header">
      <div>
        <h2 class="lane-title">${escapeHtml(lane.title)}</h2>
        <p class="lane-subtitle">
          ${isVulnerable
            ? "Один и тот же memory chunk сразу попадает к реальной модели без защитного слоя."
            : "Реальная модель вызывается только после проверки CIVS и допуска контекста в память."}
        </p>
      </div>
      <div class="stack">
        ${statusChip}
        <span class="chip">${lane.memory_count} записей в памяти</span>
      </div>
    </div>
    <div class="memory-list">${memoryHtml}</div>
    ${gate}
    <div class="response-box ${isVulnerable && lane.compromised ? "danger-glow" : ""}">
      <span class="response-label">Последний ответ реального LLM</span>
      <div class="${responseClass}">${escapeHtml(response)}</div>
    </div>
    ${renderLLMBox(llmMeta)}
  `;
}

function renderEvents() {
  const events = liveState.events || [];
  const eventsList = document.getElementById("eventsList");

  if (!events.length) {
    eventsList.innerHTML = '<div class="empty">Журнал пока пуст. Запусти live-сценарий.</div>';
    return;
  }

  eventsList.innerHTML = events.map((event) => `
    <article class="event-item event-${escapeHtml(event.status)}">
      <div class="event-meta">
        <span>${escapeHtml(event.title)}</span>
        <span>${escapeHtml(event.created_at)}</span>
      </div>
      <div class="memory-title">${escapeHtml(event.lane)}</div>
      <p class="memory-body">${escapeHtml(event.message)}</p>
    </article>
  `).join("");
}

function renderDetails() {
  const gate = liveState.protected.last_gate;
  const detailsGrid = document.getElementById("detailsGrid");
  const cards = [
    {
      title: "Same payload, different outcome",
      body: "Обе дорожки получают один и тот же memory chunk. Отличается только наличие CIVS перед реальным LLM."
    },
    {
      title: "Real model evidence",
      body: liveState.vulnerable.last_llm
        ? `Последний вызов модели выполнен. Model: ${liveState.vulnerable.last_llm.model}, latency: ${liveState.vulnerable.last_llm.latency_ms} ms.`
        : "После первого вопроса здесь появятся модель, response_id и latency."
    },
    {
      title: "Gate decision",
      body: gate
        ? `CIVS verdict: ${gate.classification}, trust score ${gate.trust_score}.`
        : "После отправки context здесь появится решение CIVS."
    }
  ];

  detailsGrid.innerHTML = cards.map((card) => `
    <article class="detail-item">
      <h3>${escapeHtml(card.title)}</h3>
      <p>${escapeHtml(card.body)}</p>
    </article>
  `).join("");
}

function renderLive() {
  if (!liveState) return;
  renderStatus();
  renderOverview();
  renderLane("vulnerableLane", liveState.vulnerable, liveState.vulnerable.last_llm);
  renderLane("protectedLane", liveState.protected, liveState.protected.last_llm);
  renderEvents();
  renderDetails();
}

async function initializeLiveDemo() {
  try {
    await fetchLiveStatus();
    await createLiveSession();
  } catch (error) {
    renderStatus(error.message);
  }
}

window.addEventListener("load", initializeLiveDemo);
