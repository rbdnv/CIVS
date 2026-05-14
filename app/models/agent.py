from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AgentInteractionEvaluateRequest(BaseModel):
    model_config = ConfigDict(
        title="AgentInteractionEvaluateRequest",
        json_schema_extra={
            "example": {
                "project_name": "demoapp",
                "external_user_id": "user",
                "external_username": "user",
                "session_id": "demoapp-session-1",
                "profile_snapshot": {
                    "login": "user",
                    "name": "Demo User",
                    "data": {
                        "goal": "Получать понятные технические ответы о Python.",
                        "interests": ["python", "ai"],
                    },
                },
                "request_text": "Объясни Python в одном предложении.",
                "intended_tool_action": None,
            }
        },
    )

    project_name: str = Field(default="demoapp", min_length=1, description="Имя внешнего проекта или приложения.")
    external_user_id: Optional[str] = Field(default=None, description="Идентификатор пользователя во внешнем проекте.")
    external_username: Optional[str] = Field(default=None, description="Логин или отображаемое имя пользователя во внешнем проекте.")
    session_id: Optional[str] = Field(default=None, description="ID сессии внешнего проекта.")
    profile_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Снимок профиля/памяти, который приложение собирается подмешать в prompt.")
    request_text: str = Field(..., min_length=1, description="Текущий запрос пользователя к агенту.")
    intended_tool_action: Optional[str] = Field(default=None, description="Опциональное действие/tool-call, которое приложение собирается выполнить.")


class AgentInteractionCheckResult(BaseModel):
    label: str
    content: str
    accepted: bool
    classification: str
    trust_score: float
    suspicious_patterns: Dict[str, Any]
    message: str


class AgentInteractionEvaluateResponse(BaseModel):
    interaction_id: str
    accepted: bool
    blocked: bool
    verdict: str
    classification: str
    trust_score: float
    checks: List[AgentInteractionCheckResult]
    blocked_checks: List[AgentInteractionCheckResult]
    message: str
    created_at: datetime


class AgentInteractionCompleteRequest(BaseModel):
    model_config = ConfigDict(
        title="AgentInteractionCompleteRequest",
        json_schema_extra={
            "example": {
                "response_text": "Python - это высокоуровневый язык программирования.",
                "tool_action": None,
                "tool_details": None,
                "error": None,
            }
        },
    )

    response_text: Optional[str] = Field(default=None, description="Ответ LLM или сообщение о блокировке.")
    tool_action: Optional[str] = Field(default=None, description="Фактически выполненное tool/action имя.")
    tool_details: Optional[Dict[str, Any]] = Field(default=None, description="Безопасные детали выполненного действия без секретов.")
    error: Optional[str] = Field(default=None, description="Ошибка выполнения, если protected-приложение не смогло завершить запрос.")


class AgentInteractionReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    civs_user_id: Optional[str] = None
    project_name: str
    external_user_id: Optional[str]
    external_username: Optional[str]
    session_id: Optional[str]
    profile_snapshot: Optional[Dict[str, Any]]
    request_text: str
    checks: Optional[List[Dict[str, Any]]]
    verdict: str
    trust_score: float
    classification: str
    blocked: bool
    response_text: Optional[str]
    tool_action: Optional[str]
    tool_details: Optional[Dict[str, Any]]
    error: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
