from sqlalchemy import create_engine, Column, String, DateTime, Text, Float, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
import uuid

Base = declarative_base()


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    contexts = relationship("ContextRecord", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class DataSource(Base):
    __tablename__ = "data_sources"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    source_type = Column(String, nullable=False)  # rag, manual, external
    config = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    contexts = relationship("ContextRecord", back_populates="data_source")


class ContextRecord(Base):
    __tablename__ = "context_records"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(String, nullable=True, index=True)
    parent_context_id = Column(String, nullable=True)
    
    # Content
    content = Column(Text, nullable=False)
    content_hash = Column(String, nullable=False, index=True)
    previous_hash = Column(String, nullable=True)
    
    # Metadata - renamed to avoid SQLAlchemy reserved name conflict
    context_metadata = Column(JSON, nullable=True)
    context_type = Column(String, default="general")
    priority = Column(Integer, default=0)
    flags = Column(JSON, nullable=True)
    
    # Trust score
    trust_score = Column(Float, nullable=True)
    classification = Column(String, nullable=True)  # ACCEPT, QUARANTINE, REJECT
    
    # Security
    data_source_id = Column(String, ForeignKey("data_sources.id"), nullable=True)
    source_ip = Column(String, nullable=True)
    
    # Signature
    signature = Column(Text, nullable=True)
    public_key = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    verified_at = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="contexts")
    data_source = relationship("DataSource", back_populates="contexts")
    hash_records = relationship("HashRecord", back_populates="context")
    signature_record = relationship("SignatureRecord", back_populates="context")
    verification_results = relationship("VerificationResult", back_populates="context")


class HashRecord(Base):
    __tablename__ = "hash_records"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    context_id = Column(String, ForeignKey("context_records.id"), nullable=False, index=True)
    
    content = Column(Text, nullable=False)
    hash_value = Column(String, nullable=False, index=True)
    previous_hash = Column(String, nullable=True)
    sequence_number = Column(Integer, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    context = relationship("ContextRecord", back_populates="hash_records")


class SignatureRecord(Base):
    __tablename__ = "signature_records"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    context_id = Column(String, ForeignKey("context_records.id"), nullable=False, index=True)
    
    algorithm = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
    public_key = Column(String, nullable=False)
    is_valid = Column(Boolean, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    context = relationship("ContextRecord", back_populates="signature_record")


class VerificationResult(Base):
    __tablename__ = "verification_results"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    context_id = Column(String, ForeignKey("context_records.id"), nullable=False, index=True)
    
    trust_score = Column(Float, nullable=False)
    classification = Column(String, nullable=False)
    is_valid = Column(Boolean, nullable=False)
    
    # Attack detection
    tampering_detected = Column(Boolean, default=False)
    replay_attack_detected = Column(Boolean, default=False)
    
    # Details
    details = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    context = relationship("ContextRecord", back_populates="verification_results")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    event_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)  # low, medium, high, critical
    
    # Context info
    context_id = Column(String, nullable=True, index=True)
    user_id = Column(String, nullable=True, index=True)
    
    # Details
    description = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    
    action = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=True, index=True)
    
    # Details
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    user = relationship("User", back_populates="audit_logs")


class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    
    # Key info
    public_key = Column(Text, nullable=False)
    key_type = Column(String, nullable=False)  # Ed25519, ECDSA
    
    # Validity
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Metadata - renamed to avoid SQLAlchemy reserved name
    cert_metadata = Column(JSON, nullable=True)
