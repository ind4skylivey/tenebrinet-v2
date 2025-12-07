# tests/unit/services/test_ssh_honeypot.py
"""
Unit tests for SSH Honeypot service.
"""
import pytest

from tenebrinet.services.ssh.server import (
    SSHHoneypot,
    SSHHoneypotServer,
)
from tenebrinet.core.config import SSHServiceConfig


@pytest.fixture
def ssh_config():
    """Create a test SSH configuration."""
    return SSHServiceConfig(
        enabled=True,
        port=2222,
        host="127.0.0.1",
        banner="OpenSSH_8.9",
    )


@pytest.fixture
def ssh_honeypot(ssh_config):
    """Create a test SSH honeypot instance."""
    return SSHHoneypot(ssh_config)


class TestSSHHoneypot:
    """Tests for SSHHoneypot class."""

    def test_initialization(self, ssh_honeypot, ssh_config):
        """Test honeypot initializes with correct config."""
        assert ssh_honeypot.host == ssh_config.host
        assert ssh_honeypot.port == ssh_config.port
        assert ssh_honeypot.banner == ssh_config.banner
        assert ssh_honeypot._running is False

    def test_health_check_not_running(self, ssh_honeypot):
        """Test health check when not running."""
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            ssh_honeypot.health_check()
        )
        assert result["service"] == "ssh_honeypot"
        assert result["running"] is False
        assert result["port"] == 2222


class TestSSHHoneypotServer:
    """Tests for SSHHoneypotServer class."""

    def test_password_auth_supported(self, ssh_honeypot):
        """Test that password auth is supported."""
        server = SSHHoneypotServer(ssh_honeypot)
        assert server.password_auth_supported() is True

    def test_begin_auth_returns_true(self, ssh_honeypot):
        """Test that begin_auth allows authentication."""
        server = SSHHoneypotServer(ssh_honeypot)
        result = server.begin_auth("testuser")
        assert result is True

    def test_server_initialization(self, ssh_honeypot):
        """Test server initializes properly."""
        server = SSHHoneypotServer(ssh_honeypot)
        assert server.honeypot == ssh_honeypot
        assert server.client_ip is None
        assert server.attack_id is None
