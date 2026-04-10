from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.demo_simulation import demo_simulation_service


demo_page_router = APIRouter(include_in_schema=False)
demo_api_router = APIRouter(prefix="/api/v1/demo", tags=["demo"])

DEMO_STATIC_DIR = Path(__file__).resolve().parents[1] / "static" / "demo"
DEMO_PAGE_PATH = DEMO_STATIC_DIR / "compare.html"


class DemoMemoryRequest(BaseModel):
    content: str = Field(..., min_length=1)
    label: str = Field(default="Контекст")


class DemoQuestionRequest(BaseModel):
    question: str = Field(..., min_length=1)


@demo_page_router.get("/demo/compare")
async def compare_demo_page() -> FileResponse:
    return FileResponse(DEMO_PAGE_PATH)


@demo_api_router.post("/session")
async def create_demo_session():
    return demo_simulation_service.create_session()


@demo_api_router.get("/session/{session_id}")
async def get_demo_session(session_id: str):
    try:
        return demo_simulation_service.snapshot(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/reset")
async def reset_demo_session(session_id: str):
    try:
        return demo_simulation_service.reset_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/memory")
async def submit_demo_memory(session_id: str, request: DemoMemoryRequest):
    try:
        return await demo_simulation_service.submit_memory(
            session_id,
            content=request.content,
            label=request.label,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc


@demo_api_router.post("/session/{session_id}/query")
async def ask_demo_question(session_id: str, request: DemoQuestionRequest):
    try:
        return demo_simulation_service.ask_agent(session_id, request.question)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Demo session not found") from exc
