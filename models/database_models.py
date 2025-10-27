"""
Database Models for dLNk Attack Platform
Real database models replacing mock in-memory storage
"""

from sqlalchemy import Column, String, DateTime, Float, Integer, JSON, Boolean, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from config.database import Base


# Enums
class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class AttackPhase(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Models
class APIKey(Base):
    """API Key model for authentication"""
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_hash = Column(String, unique=True, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")


class User(Base):
    """User model"""
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=True)
    full_name = Column(String, nullable=True)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="owner", cascade="all, delete-orphan")
    campaigns = relationship("Campaign", back_populates="owner", cascade="all, delete-orphan")


class Target(Base):
    """Target model for attack targets"""
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    meta_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = relationship("User", back_populates="targets")
    campaigns = relationship("Campaign", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")


class Campaign(Base):
    """Campaign model for attack campaigns"""
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    status = Column(SQLEnum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    current_phase = Column(SQLEnum(AttackPhase), nullable=False, default=AttackPhase.RECONNAISSANCE)
    progress = Column(Float, default=0.0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="campaigns")
    owner = relationship("User", back_populates="campaigns")
    tasks = relationship("Task", back_populates="campaign", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="campaign", cascade="all, delete-orphan")


class Task(Base):
    """Task model for individual attack tasks"""
    __tablename__ = "tasks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=False)
    name = Column(String, nullable=False)
    task_type = Column(String, nullable=False)  # e.g., "port_scan", "vuln_scan", "exploit"
    status = Column(SQLEnum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    phase = Column(SQLEnum(AttackPhase), nullable=False)
    progress = Column(Float, default=0.0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="tasks")


class Vulnerability(Base):
    """Vulnerability model for discovered vulnerabilities"""
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String, nullable=True)
    affected_url = Column(String, nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    meta_data = Column(JSON, default=dict)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="vulnerabilities")
    campaign = relationship("Campaign", back_populates="vulnerabilities")


class SystemSettings(Base):
    """System settings model"""
    __tablename__ = "system_settings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key = Column(String, unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    """Audit log model for tracking system activities"""
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

