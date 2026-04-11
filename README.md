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

### 1. Запуск PostgreSQL
```bash
docker compose up -d postgres
```

### 2. Запуск API сервера
```bash
python -m uvicorn app.main:app --reload --port 8000
```

### 3. Открыть документацию
http://localhost:8000/docs

### 4. Открыть интерактивную демонстрацию
http://localhost:8000/demo/compare

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
| POST | `/api/v1/security/check-content` | Проверить контент |
| GET | `/api/v1/health` | Проверка здоровья |

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
│   │   ├── verifier.py      # Trust Score
│   │   └── security.py      # Защита от атак
│   ├── db/
│   │   ├── database.py      # PostgreSQL подключение
│   │   └── tables.py        # Модели БД
│   └── models/
│       └── context.py       # Pydantic модели
│   └── static/demo/         # HTML/CSS/JS демонстрации
├── tests/
│   ├── test_core.py         # Core unit-тесты
│   ├── test_auth.py         # Auth unit-тесты
│   └── test_demo_simulation.py # Demo flow unit-тесты
├── docker-compose.yml      # PostgreSQL
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
