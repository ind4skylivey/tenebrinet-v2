# tests/unit/core/test_models.py
"""Unit tests for TenebriNET ORM models."""
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import RelationshipProperty
from sqlalchemy.sql.schema import CallableColumnDefault
from sqlalchemy.sql.sqltypes import Boolean, DateTime, Float, Integer, JSON, String

from tenebrinet.core.database import Base
from tenebrinet.core.models import Attack, Credential, Session


class TestAttackModel:
    """Tests for the Attack model."""

    def test_column_definitions(self):
        """Test the Attack model's column definitions and types."""
        assert isinstance(Attack.__table__.columns.id.type, postgresql.UUID)
        assert Attack.__table__.columns.id.primary_key

        # Check that the default is a callable
        assert isinstance(
            Attack.__table__.columns.id.default, CallableColumnDefault
        )

        assert isinstance(Attack.__table__.columns.ip.type, String)
        assert Attack.__table__.columns.ip.nullable is False
        assert Attack.__table__.columns.ip.index

        assert isinstance(Attack.__table__.columns.timestamp.type, DateTime)
        assert isinstance(
            Attack.__table__.columns.timestamp.default, CallableColumnDefault
        )
        assert Attack.__table__.columns.timestamp.index

        assert isinstance(Attack.__table__.columns.service.type, String)
        assert Attack.__table__.columns.service.nullable is False

        assert isinstance(Attack.__table__.columns.payload.type, JSON)
        assert isinstance(Attack.__table__.columns.threat_type.type, String)
        assert isinstance(Attack.__table__.columns.confidence.type, Float)
        assert isinstance(Attack.__table__.columns.country.type, String)
        assert isinstance(Attack.__table__.columns.asn.type, Integer)

    def test_relationships(self):
        """Test Attack model relationships."""
        assert isinstance(
            Attack.sessions.property, RelationshipProperty
        )
        assert Attack.sessions.property.back_populates == "attack"

        assert isinstance(
            Attack.credentials.property, RelationshipProperty
        )
        assert Attack.credentials.property.back_populates == "attack"

    def test_repr(self):
        """Test Attack __repr__ method."""
        attack_id = uuid.uuid4()
        attack = Attack(
            id=attack_id,
            ip="127.0.0.1",
            service="ssh",
            threat_type="brute_force",
        )
        repr_str = repr(attack)
        assert str(attack_id) in repr_str
        assert "127.0.0.1" in repr_str
        assert "ssh" in repr_str
        assert "brute_force" in repr_str


class TestSessionModel:
    """Tests for the Session model."""

    def test_column_definitions(self):
        """Test the Session model's column definitions and types."""
        assert isinstance(Session.__table__.columns.id.type, postgresql.UUID)
        assert Session.__table__.columns.id.primary_key
        assert isinstance(
            Session.__table__.columns.id.default, CallableColumnDefault
        )

        assert isinstance(
            Session.__table__.columns.attack_id.type, postgresql.UUID
        )
        # Check foreign key
        fk_col = next(
            iter(Session.__table__.columns.attack_id.foreign_keys)
        ).column
        assert isinstance(fk_col.type, postgresql.UUID)

        assert isinstance(Session.__table__.columns.start_time.type, DateTime)
        assert isinstance(
            Session.__table__.columns.start_time.default, CallableColumnDefault
        )
        assert isinstance(Session.__table__.columns.end_time.type, DateTime)
        assert isinstance(Session.__table__.columns.commands.type, JSON)

    def test_relationships(self):
        """Test Session model relationships."""
        assert isinstance(Session.attack.property, RelationshipProperty)
        assert Session.attack.property.back_populates == "sessions"

    def test_repr(self):
        """Test Session __repr__ method."""
        session_id = uuid.uuid4()
        attack_id = uuid.uuid4()
        start = datetime.now(timezone.utc)
        session = Session(
            id=session_id,
            attack_id=attack_id,
            start_time=start,
        )
        repr_str = repr(session)
        assert str(session_id) in repr_str
        assert str(attack_id) in repr_str


class TestCredentialModel:
    """Tests for the Credential model."""

    def test_column_definitions(self):
        """Test the Credential model's column definitions and types."""
        assert isinstance(
            Credential.__table__.columns.id.type, postgresql.UUID
        )
        assert Credential.__table__.columns.id.primary_key
        assert isinstance(
            Credential.__table__.columns.id.default, CallableColumnDefault
        )

        assert isinstance(
            Credential.__table__.columns.attack_id.type, postgresql.UUID
        )
        # Check foreign key
        fk_col = next(
            iter(Credential.__table__.columns.attack_id.foreign_keys)
        ).column
        assert isinstance(fk_col.type, postgresql.UUID)

        assert isinstance(Credential.__table__.columns.username.type, String)
        assert Credential.__table__.columns.username.nullable is False
        assert isinstance(Credential.__table__.columns.password.type, String)
        assert Credential.__table__.columns.password.nullable is False
        assert isinstance(Credential.__table__.columns.success.type, Boolean)
        assert Credential.__table__.columns.success.default.arg is False

    def test_relationships(self):
        """Test Credential model relationships."""
        assert isinstance(Credential.attack.property, RelationshipProperty)
        assert Credential.attack.property.back_populates == "credentials"

    def test_repr(self):
        """Test Credential __repr__ method."""
        cred_id = uuid.uuid4()
        attack_id = uuid.uuid4()
        cred = Credential(
            id=cred_id,
            attack_id=attack_id,
            username="testuser",
            password="testpass",
            success=True,
        )
        repr_str = repr(cred)
        assert str(cred_id) in repr_str
        assert str(attack_id) in repr_str
        assert "testuser" in repr_str
        assert "True" in repr_str
