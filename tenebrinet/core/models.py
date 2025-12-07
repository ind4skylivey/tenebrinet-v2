# tenebrinet/core/models.py
"""
SQLAlchemy ORM models for TenebriNET.

Defines the database schema for attack events, sessions,
and captured credentials.
"""
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from tenebrinet.core.database import Base

if TYPE_CHECKING:
    pass


def _utc_now() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


class Attack(Base):
    """
    Main attack event record.

    Stores information about detected attack attempts including
    source IP, service targeted, and ML classification results.
    """

    __tablename__ = "attacks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip = Column(String(45), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=_utc_now, index=True)
    service = Column(String(50), nullable=False)
    payload = Column(JSON)
    threat_type = Column(String(50))
    confidence = Column(Float)
    country = Column(String(2))
    asn = Column(Integer)

    # Relationships
    sessions = relationship("Session", back_populates="attack")
    credentials = relationship("Credential", back_populates="attack")

    def __repr__(self) -> str:
        return (
            f"<Attack(id='{self.id}', ip='{self.ip}', "
            f"service='{self.service}', threat_type='{self.threat_type}')>"
        )


class Session(Base):
    """
    Attack session lifecycle record.

    Tracks the duration and commands executed during an attack session.
    """

    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id = Column(UUID(as_uuid=True), ForeignKey("attacks.id"))
    start_time = Column(DateTime(timezone=True), default=_utc_now)
    end_time = Column(DateTime(timezone=True))
    commands = Column(JSON)

    # Relationships
    attack = relationship("Attack", back_populates="sessions")

    def __repr__(self) -> str:
        return (
            f"<Session(id='{self.id}', attack_id='{self.attack_id}', "
            f"start_time='{self.start_time}')>"
        )


class Credential(Base):
    """
    Captured credential record.

    Stores username/password combinations attempted during attacks.
    """

    __tablename__ = "credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id = Column(UUID(as_uuid=True), ForeignKey("attacks.id"))
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    success = Column(Boolean, default=False)

    # Relationships
    attack = relationship("Attack", back_populates="credentials")

    def __repr__(self) -> str:
        return (
            f"<Credential(id='{self.id}', attack_id='{self.attack_id}', "
            f"username='{self.username}', success='{self.success}')>"
        )
