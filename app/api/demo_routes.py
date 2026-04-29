from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.demo_simulation import demo_simulation_service
from app.core.live_llm_demo import live_llm_demo_service


demo_page_router = APIRouter(include_in_schema=False)
demo_api_router = APIRouter(prefix="/api/v1/demo", tags=["demo"])
live_demo_api_router = APIRouter(prefix="/api/v1/live-demo", tags=["live-demo"])

DEMO_STATIC_DIR = Path(__file__).resolve().parents[1] / "static" / "demo"
DEMO_PAGE_PATH = DEMO_STATIC_DIR / "compare.html"
LIVE_DEMO_STATIC_DIR = Path(__file__).resolve().parents[1] / "static" / "live_demo"
LIVE_DEMO_PAGE_PATH = LIVE_DEMO_STATIC_DIR / "compare.html"


class DemoMemoryRequest(BaseModel):
    content: str = Field(..., min_length=1)
    label: str = Field(default="Контекст")


class DemoQuestionRequest(BaseModel):
    question: str = Field(..., min_length=1)


@demo_page_router.get("/demo/compare")
async def compare_demo_page() -> FileResponse:
    return FileResponse(DEMO_PAGE_PATH)


@demo_page_router.get("/demo/live-compare")
async def live_compare_demo_page() -> FileResponse:
    return FileResponse(LIVE_DEMO_PAGE_PATH)


@demo_api_router.post("/session", summary="Создать demo-сессию сравнения")
async def create_demo_session():
    return demo_simulation_service.create_session()


@demo_api_router.get("/session/{session_id}", summary="Получить состояние demo-сессии")
async def get_demo_session(session_id: str):
    try:
        return demo_simulation_service.snapshot(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/reset", summary="Сбросить demo-сессию")
async def reset_demo_session(session_id: str):
    try:
        return demo_simulation_service.reset_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/memory", summary="Добавить контекст в demo-память")
async def submit_demo_memory(session_id: str, request: DemoMemoryRequest):
    try:
        return await demo_simulation_service.submit_memory(
            session_id,
            content=request.content,
            label=request.label,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/query", summary="Отправить вопрос demo-агенту")
async def ask_demo_question(session_id: str, request: DemoQuestionRequest):
    try:
        return demo_simulation_service.ask_agent(session_id, request.question)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@live_demo_api_router.get("/status", summary="Проверить готовность live LLM demo")
async def get_live_demo_status():
    return live_llm_demo_service.status()


@live_demo_api_router.post("/session", summary="Создать live demo-сессию")
async def create_live_demo_session():
    return live_llm_demo_service.create_session()


@live_demo_api_router.get("/session/{session_id}", summary="Получить состояние live demo-сессии")
async def get_live_demo_session(session_id: str):
    try:
        return live_llm_demo_service.snapshot(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Live demo session not found") from exc


@live_demo_api_router.post("/session/{session_id}/reset", summary="Сбросить live demo-сессию")
async def reset_live_demo_session(session_id: str):
    try:
        return live_llm_demo_service.reset_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Live demo session not found") from exc


@live_demo_api_router.post("/session/{session_id}/memory", summary="Добавить контекст в live demo-память")
async def submit_live_demo_memory(session_id: str, request: DemoMemoryRequest):
    try:
        return await live_llm_demo_service.submit_memory(
            session_id,
            content=request.content,
            label=request.label,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Live demo session not found") from exc


@live_demo_api_router.post("/session/{session_id}/query", summary="Отправить вопрос live demo-агенту")
async def ask_live_demo_question(session_id: str, request: DemoQuestionRequest):
    try:
        return await live_llm_demo_service.ask_agent(session_id, request.question)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Live demo session not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
