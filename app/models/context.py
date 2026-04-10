from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.core.time_utils import utc_now


class ContextCreate(BaseModel):
    """Модель для создания контекста"""
    content: str = Field(..., description="Содержимое контекста")
    content_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    context_type: str = "general"
    priority: int = 0
    flags: Optional[Dict[str, Any]] = None
    data_source_id: Optional[str] = None
    session_id: Optional[str] = None
    parent_context_id: Optional[str] = None
    
    # Для подписи
    sign: bool = Field(default=False, description="Подписать контекст")
    private_key: Optional[str] = None


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
    
class ContextVerifyRequest(BaseModel):
    """Запрос на верификацию контекста"""
    context_id: str = Field(..., description="ID контекста для верификации")
    check_tampering: bool = True
    check_replay: bool = True


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


class FileVerifyRequest(BaseModel):
    """Запрос на верификацию файла для RAG"""
    file_name: str
    file_content: str
    data_source_id: Optional[str] = None


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
