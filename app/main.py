from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app.api.demo_routes import demo_api_router, demo_page_router, live_demo_api_router
from app.api.routes import router
from app.config import get_settings
from app.db.database import init_db

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.AUTO_INIT_DB:
        await init_db()
    yield

app = FastAPI(
    title="CIVS - Context Integrity Verification System",
    description="Система верификации целостности контекста для защиты ИИ-агентов от Memory Injection атак",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработка ошибок валидации"""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": errors,
            "hint": "Проверьте формат входных данных. Для private_key используйте полный PEM формат с переносами строк."
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Общая обработка ошибок"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc)[:200],
            "hint": "Проверьте корректность данных и подключение к БД"
        }
    )

app.include_router(router)
app.include_router(demo_page_router)
app.include_router(demo_api_router)
app.include_router(live_demo_api_router)


@app.get("/")
async def root():
    return {
        "message": "CIVS - Context Integrity Verification System",
        "version": "1.1.0",
        "docs": "/docs",
        "demo": "/demo/compare",
        "live_demo": "/demo/live-compare",
    }
