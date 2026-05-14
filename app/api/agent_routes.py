from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_gateway import agent_gateway_service, build_evaluate_response
from app.core.auth import get_current_admin, get_current_user
from app.db.database import get_db
from app.models.agent import (
    AgentInteractionCompleteRequest,
    AgentInteractionEvaluateRequest,
    AgentInteractionEvaluateResponse,
    AgentInteractionReportResponse,
)
from app.models.context import ErrorResponse


agent_router = APIRouter(prefix="/api/v1", tags=["agent-gateway"])

AGENT_INTERACTION_NOT_FOUND_RESPONSE = {
    "model": ErrorResponse,
    "description": "Agent interaction with the requested ID was not found",
    "content": {
        "application/json": {
            "example": {
                "detail": "Agent interaction not found",
            }
        }
    },
}

ADMIN_FORBIDDEN_RESPONSE = {
    "model": ErrorResponse,
    "description": "Admin privileges required",
    "content": {
        "application/json": {
            "example": {
                "detail": "Admin privileges required",
            }
        }
    },
}


@agent_router.post(
    "/agent/interactions/evaluate",
    response_model=AgentInteractionEvaluateResponse,
    summary="Evaluate an external AI-agent request before LLM execution",
    description=(
        "Server-side CIVS gateway endpoint for external projects. It checks profile "
        "context and the current question, stores an interaction report, and returns "
        "whether the protected application may call its LLM."
    ),
)
async def evaluate_agent_interaction(
    request: AgentInteractionEvaluateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    interaction = await agent_gateway_service.evaluate_interaction(request, db, current_user)
    return build_evaluate_response(interaction)


@agent_router.post(
    "/agent/interactions/{interaction_id}/complete",
    response_model=AgentInteractionReportResponse,
    summary="Complete an external AI-agent interaction report",
    description=(
        "Called by the protected application after a request is blocked, answered by "
        "the LLM, or completed with an application/tool error."
    ),
    responses={404: AGENT_INTERACTION_NOT_FOUND_RESPONSE},
)
async def complete_agent_interaction(
    interaction_id: str,
    request: AgentInteractionCompleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        return await agent_gateway_service.complete_interaction(interaction_id, request, db, current_user)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent interaction not found",
        ) from exc
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@agent_router.get(
    "/admin/interactions",
    response_model=List[AgentInteractionReportResponse],
    summary="List external AI-agent interaction reports",
    description="Admin-only report feed for requests evaluated by the CIVS gateway.",
    tags=["admin"],
    responses={403: ADMIN_FORBIDDEN_RESPONSE},
)
async def list_agent_interactions(
    project_name: Optional[str] = Query(default=None),
    external_user_id: Optional[str] = Query(default=None),
    session_id: Optional[str] = Query(default=None),
    blocked: Optional[bool] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_admin),
):
    return await agent_gateway_service.list_interactions(
        db,
        project_name=project_name,
        external_user_id=external_user_id,
        session_id=session_id,
        blocked=blocked,
        limit=limit,
    )


@agent_router.get(
    "/admin/interactions/{interaction_id}",
    response_model=AgentInteractionReportResponse,
    summary="Get one external AI-agent interaction report",
    description="Admin-only detailed report for one CIVS gateway interaction.",
    tags=["admin"],
    responses={
        403: ADMIN_FORBIDDEN_RESPONSE,
        404: AGENT_INTERACTION_NOT_FOUND_RESPONSE,
    },
)
async def get_agent_interaction(
    interaction_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_admin),
):
    try:
        return await agent_gateway_service.get_interaction(interaction_id, db)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent interaction not found",
        ) from exc
