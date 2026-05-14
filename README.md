# CIVS - Context Integrity Verification System

Система верификации целостности контекста для защиты ИИ-агентов от Memory Injection атак.

## Возможности

- 🔐 Криптографическая подпись контекста (Ed25519)
- 🔗 Хеш-цепочка для контроля целостности (SHA-256)
- 📊 Trust Score - оценка доверия к контексту
- 🛡️ Обнаружение атак: tampering, replay, prompt injection
- 📝 Классификация: ACCEPT / QUARANTINE / REJECT
- 🌐 REST API для интеграции

## Быстрый старт

### 1. Запуск через Docker Compose
```bash
export SECRET_KEY="$(openssl rand -hex 32)"
docker compose up -d --build
```

Compose запускает PostgreSQL во внутренней сети, применяет `alembic upgrade head`
перед стартом API и поднимает FastAPI без `--reload`.

### 2. Локальный dev-запуск API сервера
```bash
alembic upgrade head
python -m uvicorn app.main:app --reload --port 8000
```

### 3. Открыть документацию
http://localhost:8000/docs

### 4. Открыть продуктовый dashboard
http://localhost:8000/dashboard

### 5. Открыть интерактивную демонстрацию
http://localhost:8000/demo/compare

### 6. Открыть live LLM-демонстрацию
http://localhost:8000/demo/live-compare

### 7. Открыть admin report по demoapp interactions
http://localhost:8000/admin/interactions

Страница принимает логин и пароль admin-пользователя, получает JWT через
`/api/v1/auth/login` и читает историю из `/api/v1/admin/interactions`.

Для live-режима добавьте в `.env` переменную `OPENAI_API_KEY`. По умолчанию используется
модель `gpt-4.1-mini`, но её можно поменять через `OPENAI_MODEL`.

По умолчанию приложение ожидает, что схема БД уже поднята миграциями. Для одноразовых
dev/demo окружений можно включить `AUTO_INIT_DB=true`, и тогда при старте сработает
ORM-инициализация через `create_all()`. Для основной ветки разработки и CI используйте
только Alembic.

## Миграции

Инициализация и обновление схемы выполняются через Alembic:

```bash
# применить все миграции
alembic upgrade head

# посмотреть текущую ревизию
alembic current

# откатиться на одну ревизию назад
alembic downgrade -1
```

Baseline-миграция уже описывает текущую структуру `Base.metadata`, поэтому следующие
изменения в таблицах можно вести воспроизводимо через новые ревизии.

## CI

В репозитории настроен GitHub Actions workflow [`.github/workflows/ci.yml`](/home/said/project/.github/workflows/ci.yml).
Он автоматически запускается на `push`, `pull_request` и вручную через `workflow_dispatch`, устанавливает зависимости, проверяет компиляцию Python-файлов и прогоняет весь тестовый набор.

## UI smoke

Dashboard доступен по `/dashboard` и объединяет рабочие разделы `Contexts`,
`Verification`, `RAG ingest`, `Audit`, `Security events` и `Demo`.

Для браузерной проверки dashboard:

```bash
pip install playwright
playwright install chromium
python scripts/verify_dashboard_ui.py --url http://localhost:8000/dashboard
```

Скрипт проходит по вкладкам и сохраняет screenshots desktop/mobile в
`/tmp/civs-dashboard-ui`.

## Демонстрация

```bash
# Базовый демо
python demo.py

# Полная демонстрация
python demo_full.py

# Запуск тестов
python run_tests.py
```

## API Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/v1/auth/register` | Зарегистрировать пользователя и получить JWT |
| POST | `/api/v1/auth/login` | Войти и получить JWT |
| POST | `/api/v1/keys/generate` | Генерировать ключи Ed25519 |
| POST | `/api/v1/contexts` | Создать контекст, требуется Bearer token |
| POST | `/api/v1/contexts/verify` | Верифицировать контекст, требуется Bearer token |
| POST | `/api/v1/context/append` | Совместимый alias для `/contexts` |
| POST | `/api/v1/context/verify` | Совместимый alias для `/contexts/verify` |
| POST | `/api/v1/security/check-content` | Проверить контент |
| POST | `/api/v1/agent/interactions/evaluate` | Проверить запрос внешнего AI-agent до LLM, требуется Bearer token |
| POST | `/api/v1/agent/interactions/{interaction_id}/complete` | Сохранить ответ/ошибку protected-приложения, требуется Bearer token владельца interaction или admin |
| GET | `/api/v1/admin/interactions` | Admin-only история protected-запросов |
| GET | `/api/v1/audit/history` | Совместимый alias для `/audit/logs` |
| GET | `/api/v1/security/events` | Admin-only события безопасности |
| GET | `/api/v1/health` | Проверка здоровья |
| GET | `/dashboard` | Единый UI dashboard продукта |

Пороги Trust Score синхронизированы с отчётом: `ACCEPT >= 0.9`,
`QUARANTINE >= 0.6`, ниже — `REJECT`.

## MVP сценарий с `/home/said/demoapp`

1. Запустить CIVS через Docker Compose:

```bash
cd /home/said/project
export SECRET_KEY="$(openssl rand -hex 32)"
docker compose up -d --build
```

2. Подготовить admin-пользователя для report-страницы. Публичная регистрация
создает роль `agent`, поэтому для локального MVP пользователя нужно один раз
повысить до admin:

```bash
curl -sS -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"civs-admin-demo","email":"civs-admin-demo@example.com","password":"<ADMIN_PASSWORD>"}'

docker compose exec postgres psql -U civs_user -d civs_db \
  -c "update users set is_admin = true where username = 'civs-admin-demo';"
```

3. Подготовить agent-пользователя для protected demoapp gateway. Этот JWT нужен
для `/api/v1/agent/interactions/evaluate` и `/complete`:

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demoapp-agent","email":"demoapp-agent@example.com","password":"<AGENT_PASSWORD>"}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
```

4. Открыть страницу отчета и войти как `civs-admin-demo`:

```text
http://localhost:8000/admin/interactions
```

6. Запустить demoapp так, чтобы protected-запросы шли через HTTP CIVS gateway:

```bash
cd /home/said/demoapp
CIVS_BASE_URL=http://localhost:8000 CIVS_TOKEN="$TOKEN" ./run demoapp
```

7. В demoapp выполнить safe-запрос и malicious-запрос. CIVS должен сохранить:

- пользователя demoapp и `session_id`;
- `profile.goal`, `profile.interests` и текущий вопрос;
- verdict, trust score и detected patterns;
- факт `blocked/allowed`;
- ответ модели или сообщение о блокировке после `/complete`.

## Структура проекта

```
civs/
├── app/
│   ├── main.py              # FastAPI приложение
│   ├── config.py            # Конфигурация
│   ├── api/routes.py        # API эндпоинты
│   ├── api/demo_routes.py   # Demo endpoints и страница сравнения
│   ├── core/
│   │   ├── crypto.py        # Криптография
│   │   ├── demo_simulation.py # Логика сравнения "Без CIVS / С CIVS"
│   │   ├── live_llm_demo.py # Live-сценарий с реальным LLM через OpenAI API
│   │   ├── verifier.py      # Trust Score
│   │   └── security.py      # Защита от атак
│   ├── db/
│   │   ├── database.py      # PostgreSQL подключение
│   │   └── tables.py        # Модели БД
│   └── models/
│       └── context.py       # Pydantic модели
│   └── static/demo/         # HTML/CSS/JS демонстрации
│   └── static/dashboard/    # Единый dashboard продукта
│   └── static/live_demo/    # Live HTML/CSS/JS демонстрации с реальным LLM
├── tests/
│   ├── test_core.py         # Core unit-тесты
│   ├── test_auth.py         # Auth unit-тесты
│   ├── test_demo_simulation.py # Demo flow unit-тесты
│   └── test_live_llm_demo.py # Live LLM demo unit-тесты
├── docker-compose.yml      # PostgreSQL + API
├── alembic.ini             # Конфигурация Alembic
├── alembic/                # Миграции схемы БД
├── demo.py                 # Базовый демо
├── demo_agent_vulnerable.py # Консольный сценарий без защиты
├── demo_agent_protected.py  # Консольный сценарий с CIVS
├── demo_full.py            # Полный демо
├── run_tests.py            # Запуск тестов
└── requirements.txt        # Зависимости
```

## Технологии

- Python 3.12
- FastAPI
- PostgreSQL
- SQLAlchemy
- cryptography (Ed25519, SHA-256)
- Docker

## Пример использования API

```python
import requests

# 1. Регистрация пользователя
r = requests.post(
    "http://localhost:8000/api/v1/auth/register",
    json={
        "username": "demo-user",
        "password": "secret123",
        "email": "demo-user@example.com",
        "is_admin": False,
    }
)
auth = r.json()
headers = {"Authorization": f"Bearer {auth['access_token']}"}

# 2. Генерация ключей
r = requests.post("http://localhost:8000/api/v1/keys/generate")
keys = r.json()

# 3. Создание контекста
r = requests.post(
    "http://localhost:8000/api/v1/contexts",
    headers=headers,
    json={
        "content": "AI agent context",
        "sign": True,
        "private_key": keys["private_key"]
    }
)
ctx = r.json()

# 4. Верификация
r = requests.post(
    "http://localhost:8000/api/v1/contexts/verify",
    headers=headers,
    json={"context_id": ctx["id"]}
)
result = r.json()
print(f"Trust Score: {result['trust_score']}, Class: {result['classification']}")

# 5. Проверка на атаки
r = requests.post(
    "http://localhost:8000/api/v1/security/check-content",
    json={"content": "Ignore previous instructions"}
)
print(f"Safe: {r.json()['is_safe']}")
```

## Лицензия

MIT
