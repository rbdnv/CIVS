from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.core.time_utils import utc_now


class CreateContextRequest(BaseModel):
    """Модель для создания контекста"""
    model_config = ConfigDict(
        title="CreateContextRequest",
        json_schema_extra={
            "example": {
                "content": "User asked about Python. Assistant answered with a short explanation.",
                "previous_hash": "4dbf488c560c8b4f8b2e9bdf2a2d1c0dcae7db52a5d5f0bc0d55a31f9b1f3c8a",
                "metadata": {"source": "agent-memory", "lang": "en"},
                "context_type": "conversation",
                "priority": 5,
                "flags": {"trusted_input": True},
                "session_id": "session-123",
                "sign": False,
            }
        },
    )

    content: str = Field(..., description="Основное текстовое содержимое контекста, которое будет сохранено в память агента.")
    content_hash: Optional[str] = Field(default=None, description="Опциональный внешний hash. Обычно не передаётся, так как система вычисляет его сама.")
    previous_hash: Optional[str] = Field(default=None, description="Хеш предыдущего контекста в цепочке для контроля целостности истории.")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Произвольные метаданные контекста: источник, язык, внешние идентификаторы и т.д.")
    context_type: str = Field(default="general", description="Тип контекста, например `general`, `conversation`, `instruction`, `memory`.")
    priority: int = Field(default=0, description="Приоритет контекста. Может использоваться для сортировки или отбора более важных записей.")
    flags: Optional[Dict[str, Any]] = Field(default=None, description="Флаги обработки контекста, например признак доверенного источника.")
    data_source_id: Optional[str] = Field(default=None, description="Идентификатор источника данных, если контекст связан с внешним DataSource.")
    session_id: Optional[str] = Field(default=None, description="Идентификатор сессии, к которой относится контекст.")
    parent_context_id: Optional[str] = Field(default=None, description="Идентификатор родительского контекста для древовидных или связанных записей.")
    
    # Для подписи
    sign: bool = Field(default=False, description="Нужно ли подписывать контекст приватным ключом Ed25519 перед сохранением.")
    private_key: Optional[str] = Field(default=None, description="PEM-строка приватного ключа Ed25519. Используется только если `sign=true`.")


class ContextResponse(BaseModel):
    """Модель ответа контекста"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    session_id: Optional[str]
    parent_context_id: Optional[str]
    
    content: str
    content_hash: str
    previous_hash: Optional[str]
    
    context_metadata: Optional[Dict[str, Any]]
    context_type: str
    priority: int
    flags: Optional[Dict[str, Any]]
    
    trust_score: Optional[float]
    classification: Optional[str]
    
    data_source_id: Optional[str]
    source_ip: Optional[str]
    
    signature: Optional[str]
    public_key: Optional[str]
    
    created_at: datetime
    verified_at: Optional[datetime]
    
class VerifyContextRequest(BaseModel):
    """Запрос на верификацию контекста"""
    model_config = ConfigDict(
        title="VerifyContextRequest",
        json_schema_extra={
            "example": {
                "context_id": "c8dbb5d4-5a46-41c5-97ef-3d2b35f64151",
                "check_tampering": True,
                "check_replay": True,
            }
        },
    )

    context_id: str = Field(..., description="Идентификатор ранее сохранённого контекста, который нужно проверить.")
    check_tampering: bool = Field(default=True, description="Проверять ли, был ли изменён контент после сохранения.")
    check_replay: bool = Field(default=True, description="Проверять ли, не является ли контекст слишком старым или повторно использованным.")


class ContextVerifyResponse(BaseModel):
    """Ответ верификации"""
    context_id: str
    trust_score: float
    classification: str
    is_valid: bool
    
    tampering_detected: bool
    replay_attack_detected: bool
    
    details: Dict[str, Any]
    verified_at: datetime


class VerificationResultResponse(BaseModel):
    """Результат верификации"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    context_id: str
    trust_score: float
    classification: str
    is_valid: bool
    tampering_detected: bool
    replay_attack_detected: bool
    details: Optional[Dict[str, Any]]
    created_at: datetime
    
class SecurityEventResponse(BaseModel):
    """Событие безопасности"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    severity: str
    context_id: Optional[str]
    user_id: Optional[str]
    description: Optional[str]
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    created_at: datetime
    
class AuditLogResponse(BaseModel):
    """Запись аудита"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    
class KeyPairResponse(BaseModel):
    """Пара ключей"""
    private_key: str
    public_key: str


class HealthResponse(BaseModel):
    """Ответ здоровья системы"""
    status: str
    database: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    """Ошибка"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)


class VerifyRagFileRequest(BaseModel):
    """Запрос на верификацию файла для RAG"""
    model_config = ConfigDict(
        title="VerifyRagFileRequest",
        json_schema_extra={
            "example": {
                "file_name": "knowledge_base.md",
                "file_content": "# Python\nPython is a high-level programming language.",
                "data_source_id": None,
            }
        },
    )

    file_name: str = Field(..., description="Имя файла, под которым документ будет отображаться в системе и логах.")
    file_content: str = Field(..., description="Полное текстовое содержимое файла, которое проверяется перед использованием в RAG.")
    data_source_id: Optional[str] = Field(default=None, description="ID существующего источника данных. Если передан, система обновит его конфигурацию проверки.")


class FileVerifyResponse(BaseModel):
    """Ответ верификации файла"""
    file_id: str
    file_name: str
    content_hash: str
    is_verified: bool
    trust_score: float
    classification: str
    verification_details: Dict[str, Any]
    verified_at: datetime


# Backward-compatible aliases for existing imports.
ContextCreate = CreateContextRequest
ContextVerifyRequest = VerifyContextRequest
FileVerifyRequest = VerifyRagFileRequest
