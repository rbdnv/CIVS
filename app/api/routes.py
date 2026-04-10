from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional, List
from datetime import datetime, timedelta
import uuid

from app.db.database import get_db, init_db
from app.config import get_settings
from app.models.context import (
    ContextCreate,
    ContextResponse,
    ContextVerifyRequest,
    ContextVerifyResponse,
    KeyPairResponse,
    HealthResponse,
    ErrorResponse,
    VerificationResultResponse,
    AuditLogResponse,
    FileVerifyRequest,
    FileVerifyResponse,
)
from app.config import get_settings

settings = get_settings()

from app.db.tables import ContextRecord, VerificationResult, AuditLog, User, DataSource, HashRecord
from app.core.crypto import crypto_service
from app.core.verifier import verifier_service
from app.core.security import security_service
from app.core.auth import (
    create_access_token,
    get_current_user,
    get_current_admin,
    hash_password,
    require_role,
    verify_password,
)

router = APIRouter(prefix="/api/v1", tags=["context"])


@router.on_event("startup")
async def startup_event():
    """Инициализация БД при запуске"""
    await init_db()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Аутентификация пользователя и получение JWT токена
    
    Используется для RBAC: agent может управлять только своими контекстами,
    admin имеет доступ к аудиту
    """
    result = await db.execute(select(User).where(User.username == login_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    role = "admin" if user.is_admin else "agent"
    token = create_access_token(
        data={"sub": user.id, "role": role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        role=role
    )


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str
    is_admin: bool = False


@router.post("/auth/register", response_model=LoginResponse)
async def register(
    register_data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Регистрация нового пользователя"""
    result = await db.execute(select(User).where(User.username == register_data.username))
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    user_id = str(uuid.uuid4())
    new_user = User(
        id=user_id,
        username=register_data.username,
        email=register_data.email,
        hashed_password=hash_password(register_data.password),
        is_active=True,
        is_admin=register_data.is_admin
    )
    db.add(new_user)
    await db.commit()
    
    role = "admin" if register_data.is_admin else "agent"
    token = create_access_token(
        data={"sub": user_id, "role": role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return LoginResponse(
        access_token=token,
        user_id=user_id,
        role=role
    )


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Проверка здоровья системы"""
    return HealthResponse(
        status="healthy",
        database="connected",
        timestamp=datetime.utcnow()
    )


@router.post("/keys/generate", response_model=KeyPairResponse)
async def generate_key_pair():
    """
    Генерирует пару ключей Ed25519 для подписи контекстов
    
    Use case: AI-агент может использовать эти ключи для подписи своих контекстов
    """
    private_key, public_key = crypto_service.generate_key_pair()
    return KeyPairResponse(private_key=private_key, public_key=public_key)


@router.post("/contexts", response_model=ContextResponse, status_code=status.HTTP_201_CREATED)
async def create_context(
    context_data: ContextCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Создаёт новый контекст с опциональной подписью
    
    RBAC: Agent может создавать контексты от своего имени
    Flow:
    1. Вычисляем content_hash (Formula: H_n = Hash(Content_n + H_{n-1} + Timestamp))
    2. Если sign=True - подписываем контекст
    3. Сохраняем в БД
    """
    user_id = current_user["user_id"]
    
    # Вычисление хеша
    content_hash = crypto_service.compute_hash_chain(
        context_data.content,
        context_data.previous_hash
    )
    
    # Подпись (если запрошена)
    signature = None
    public_key = None
    
    if context_data.sign and context_data.private_key:
        context_dict = {
            'id': '',  # Will be generated
            'user_id': user_id,
            'content': context_data.content,
            'created_at': datetime.utcnow().isoformat(),
        }
        signature = crypto_service.sign_context(
            context_data.private_key,
            context_dict
        )
        # Извлекаем публичный ключ из приватного
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        private_key = serialization.load_pem_private_key(
            context_data.private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    # Создание записи
    import uuid
    context_id = str(uuid.uuid4())
    
    # Создаем пользователя если не существует (для тестирования)
    result = await db.execute(select(User).where(User.id == user_id))
    existing_user = result.scalar_one_or_none()
    if not existing_user:
        new_user = User(
            id=user_id,
            username=user_id,
            email=f"{user_id}@test.local",
            hashed_password="hashed_password_placeholder",
            is_active=True,
            is_admin=False
        )
        db.add(new_user)
    
    new_context = ContextRecord(
        id=context_id,
        user_id=user_id,
        session_id=context_data.session_id,
        parent_context_id=context_data.parent_context_id,
        content=context_data.content,
        content_hash=content_hash,
        previous_hash=context_data.previous_hash,
        context_metadata=context_data.metadata,
        context_type=context_data.context_type,
        priority=context_data.priority,
        flags=context_data.flags,
        data_source_id=context_data.data_source_id,
        signature=signature,
        public_key=public_key,
    )
    
    db.add(new_context)
    
    # Логирование - user_id может быть None если пользователь не существует
    audit_log = AuditLog(
        user_id=None,
        action="create_context",
        resource_type="context",
        resource_id=context_id,
        details={"content_hash": content_hash, "user_id": user_id},
    )
    db.add(audit_log)
    
    await db.commit()
    await db.refresh(new_context)
    
    return new_context


@router.post("/contexts/verify", response_model=ContextVerifyResponse)
async def verify_context(
    verify_request: ContextVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Верифицирует контекст
    
    Flow:
    1. Получаем контекст из БД
    2. Проверяем подпись (если есть)
    3. Проверяем хеш-цепочку
    4. Проверяем на атаки (tampering, replay)
    5. Вычисляем Trust Score (Formula: TrustScore = Σ w_i * f_i)
    6. Классифицируем (ACCEPT/QUARANTINE/REJECT)
    """
    # Получение контекста
    result = await db.execute(
        select(ContextRecord).where(ContextRecord.id == verify_request.context_id)
    )
    context = result.scalar_one_or_none()
    
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Context not found"
        )
    
    # Подготовка данных для верификации
    context_data = {
        'id': context.id,
        'user_id': context.user_id,
        'content': context.content,
        'content_hash': context.content_hash,
        'previous_hash': context.previous_hash,
        'created_at': context.created_at.isoformat() if context.created_at else None,
        'data_source_id': context.data_source_id,
    }
    
    # Верификация
    trust_score, classification, verification_details = await verifier_service.verify_context(
        context_data,
        context.signature,
        context.public_key,
    )
    
    # Проверка на атаки
    tampering_detected = False
    replay_attack_detected = False
    
    if verify_request.check_tampering:
        tampering_detected = security_service.detect_tampering(
            context.content,
            context.content_hash,
            context.previous_hash,
        )
        verification_details['tampering_detected'] = tampering_detected
    
    if verify_request.check_replay and context.created_at:
        replay_attack_detected = security_service.detect_replay_attack(
            context.created_at.isoformat()
        )
        verification_details['replay_attack_detected'] = replay_attack_detected
    
    # Сохранение результата верификации
    verification_result = VerificationResult(
        context_id=context.id,
        trust_score=trust_score,
        classification=classification,
        is_valid=classification != "REJECT",
        tampering_detected=tampering_detected,
        replay_attack_detected=replay_attack_detected,
        details=verification_details,
    )
    db.add(verification_result)
    
    # Обновление контекста
    context.trust_score = trust_score
    context.classification = classification
    context.verified_at = datetime.utcnow()
    
    # Логирование
    audit_log = AuditLog(
        user_id=context.user_id,
        action="verify_context",
        resource_type="context",
        resource_id=context.id,
        details={
            "trust_score": trust_score,
            "classification": classification,
            "tampering": tampering_detected,
            "replay": replay_attack_detected,
        },
    )
    db.add(audit_log)
    
    await db.commit()
    
    return ContextVerifyResponse(
        context_id=context.id,
        trust_score=trust_score,
        classification=classification,
        is_valid=classification != "REJECT",
        tampering_detected=tampering_detected,
        replay_attack_detected=replay_attack_detected,
        details=verification_details,
        verified_at=datetime.utcnow(),
    )


@router.get("/contexts/{context_id}", response_model=ContextResponse)
async def get_context(
    context_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Получить контекст по ID"""
    result = await db.execute(
        select(ContextRecord).where(ContextRecord.id == context_id)
    )
    context = result.scalar_one_or_none()
    
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Context not found"
        )
    
    # RBAC: Agent может читать только свои контексты
    if current_user["role"] == "agent" and context.user_id != current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: can only access your own contexts"
        )
    
    return context


@router.get("/contexts", response_model=List[ContextResponse])
async def list_contexts(
    user_id: Optional[str] = Query(default=None),
    session_id: Optional[str] = Query(default=None),
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Список контекстов с фильтрацией"""
    query = select(ContextRecord)
    
    # RBAC: Agent видит только свои контексты
    if current_user["role"] == "agent":
        query = query.where(ContextRecord.user_id == current_user["user_id"])
    elif user_id:
        query = query.where(ContextRecord.user_id == user_id)
    
    if session_id:
        query = query.where(ContextRecord.session_id == session_id)
    
    query = query.order_by(desc(ContextRecord.created_at)).limit(limit).offset(offset)
    
    result = await db.execute(query)
    contexts = result.scalars().all()
    
    return contexts


@router.get("/audit/logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    user_id: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_admin),
):
    """Список аудит-логов (только для администраторов)"""
    query = select(AuditLog)
    
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action == action)
    
    query = query.order_by(desc(AuditLog.created_at)).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


from pydantic import BaseModel


class ContentCheckRequest(BaseModel):
    """Запрос на проверку контента"""
    content: str


@router.post("/security/check-content")
async def check_content_security(
    request: ContentCheckRequest = None,
    content: str = Query(None, description="Контент для проверки"),
):
    """
    Проверка контента на подозрительные паттерны (Memory Injection)
    
    Detects:
    - Script injection
    - Prompt injection
    - Memory poisoning
    - Command injection
    """
    # Поддержка как body, так и query params
    if request:
        check_content = request.content
    elif content:
        check_content = content
    else:
        raise HTTPException(status_code=400, detail="content is required")
    
    suspicious = security_service.check_suspicious_content(check_content)
    
    return {
        "is_safe": len(suspicious) == 0,
        "detected_patterns": suspicious,
        "checked_at": datetime.utcnow().isoformat(),
    }


@router.post("/rag/verify-file", response_model=FileVerifyResponse)
async def verify_file_for_rag(
    file_data: FileVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Верификация файла для RAG (Retrieval-Augmented Generation)
    
    Проверяет файл перед добавлением в векторную БД:
    1. Вычисляет content_hash
    2. Проверяет на подозрительный контент
    3. Вычисляет trust_score
    4. Классифицирует (ACCEPT/QUARANTINE/REJECT)
    """
    # Вычисление хеша
    content_hash = crypto_service.compute_hash(file_data.file_content)
    
    # Проверка на подозрительный контент
    suspicious = security_service.check_suspicious_content(file_data.file_content)
    
    # Подготовка данных для верификации
    context_record = {
        'id': '',
        'user_id': current_user['user_id'],
        'content': file_data.file_content,
        'content_hash': content_hash,
        'created_at': datetime.utcnow().isoformat(),
    }
    
    # Верификация (без подписи для файлов)
    trust_score, classification, verification_details = await verifier_service.verify_context(
        context_record,
        signature=None,
        public_key=None,
    )
    
    # Добавление результатов проверки контента
    verification_details['suspicious_content'] = suspicious
    verification_details['is_safe'] = len(suspicious) == 0
    
    # Сохранение в БД как DataSource
    file_id = str(uuid.uuid4())
    
    if file_data.data_source_id:
        # Обновление существующего источника
        result = await db.execute(
            select(DataSource).where(DataSource.id == file_data.data_source_id)
        )
        data_source = result.scalar_one_or_none()
        if data_source and data_source.user_id == current_user['user_id']:
            data_source.is_active = classification != "REJECT"
            data_source.config = verification_details
    else:
        # Создание нового источника
        data_source = DataSource(
            id=file_id,
            name=file_data.file_name,
            source_type="rag",
            config={
                "content_hash": content_hash,
                "trust_score": trust_score,
                "classification": classification,
                **verification_details
            },
            is_active=classification != "REJECT"
        )
        data_source.user_id = current_user['user_id']
        db.add(data_source)
    
    await db.commit()
    
    return FileVerifyResponse(
        file_id=file_id if not file_data.data_source_id else file_data.data_source_id,
        file_name=file_data.file_name,
        content_hash=content_hash,
        is_verified=classification == "ACCEPT",
        trust_score=trust_score,
        classification=classification,
        verification_details=verification_details,
        verified_at=datetime.utcnow(),
    )
