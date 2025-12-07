# tests/unit/api/test_schemas.py
"""
Unit tests for API schemas.
"""
from datetime import datetime
from uuid import uuid4

from tenebrinet.api.schemas import (
    AttackBase,
    AttackCreate,
    AttackResponse,
    CredentialResponse,
    SessionResponse,
    AttackStats,
    ServiceStatus,
    HealthResponse,
)


class TestAttackSchemas:
    """Tests for Attack-related schemas."""

    def test_attack_base_creation(self):
        """Test AttackBase schema creation."""
        attack = AttackBase(
            ip="192.168.1.100",
            service="ssh",
            threat_type="credential_attack",
        )
        assert attack.ip == "192.168.1.100"
        assert attack.service == "ssh"
        assert attack.threat_type == "credential_attack"

    def test_attack_create_with_payload(self):
        """Test AttackCreate with payload."""
        attack = AttackCreate(
            ip="192.168.1.100",
            service="http",
            threat_type="sql_injection",
            payload={"query": "SELECT * FROM users"},
        )
        assert attack.payload == {"query": "SELECT * FROM users"}

    def test_attack_response_with_id(self):
        """Test AttackResponse includes ID and timestamps."""
        attack_id = uuid4()
        now = datetime.utcnow()
        attack = AttackResponse(
            id=attack_id,
            ip="10.0.0.1",
            service="ftp",
            threat_type="credential_attack",
            payload={},
            timestamp=now,
        )
        assert attack.id == attack_id
        assert attack.timestamp == now


class TestCredentialSchema:
    """Tests for Credential schemas."""

    def test_credential_response(self):
        """Test CredentialResponse schema."""
        cred = CredentialResponse(
            id=uuid4(),
            attack_id=uuid4(),
            username="admin",
            password="password123",
            success=False,
            timestamp=datetime.utcnow(),
        )
        assert cred.username == "admin"
        assert cred.success is False


class TestSessionSchema:
    """Tests for Session schemas."""

    def test_session_response(self):
        """Test SessionResponse schema."""
        session = SessionResponse(
            id=uuid4(),
            attack_id=uuid4(),
            commands=[{"cmd": "ls", "timestamp": "2024-12-07T12:00:00"}],
            start_time=datetime.utcnow(),
            end_time=None,
        )
        assert len(session.commands) == 1


class TestHealthSchemas:
    """Tests for Health check schemas."""

    def test_service_status(self):
        """Test ServiceStatus schema."""
        status = ServiceStatus(
            service="ssh_honeypot",
            running=True,
            host="0.0.0.0",
            port=2222,
        )
        assert status.service == "ssh_honeypot"
        assert status.running is True

    def test_health_response(self):
        """Test HealthResponse schema."""
        health = HealthResponse(
            status="healthy",
            version="0.1.0",
            database="connected",
            services=[],
            timestamp=datetime.utcnow(),
        )
        assert health.status == "healthy"


class TestAttackStats:
    """Tests for AttackStats schema."""

    def test_attack_stats(self):
        """Test AttackStats schema."""
        stats = AttackStats(
            total_attacks=100,
            attacks_today=10,
            unique_ips=50,
            top_countries=[{"country": "US", "count": 25}],
            attacks_by_service={"ssh": 40, "http": 35, "ftp": 25},
            attacks_by_threat_type={
                "credential_attack": 60, "sql_injection": 40
            },
        )
        assert stats.total_attacks == 100
        assert stats.unique_ips == 50
        assert stats.attacks_by_service["ssh"] == 40
