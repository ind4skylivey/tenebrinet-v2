# tests/unit/services/test_http_honeypot.py
"""
Unit tests for HTTP Honeypot service.
"""
import pytest

from tenebrinet.services.http.server import (
    HTTPHoneypot,
    ATTACK_PATTERNS,
    SUSPICIOUS_PATHS,
)
from tenebrinet.core.config import HTTPServiceConfig


@pytest.fixture
def http_config():
    """Create a test HTTP configuration."""
    return HTTPServiceConfig(
        enabled=True,
        port=8080,
        host="127.0.0.1",
        fake_cms="WordPress 6.4",
    )


@pytest.fixture
def http_honeypot(http_config):
    """Create a test HTTP honeypot instance."""
    return HTTPHoneypot(http_config)


class TestHTTPHoneypot:
    """Tests for HTTPHoneypot class."""

    def test_initialization(self, http_honeypot, http_config):
        """Test honeypot initializes with correct config."""
        assert http_honeypot.host == http_config.host
        assert http_honeypot.port == http_config.port
        assert http_honeypot.fake_cms == http_config.fake_cms
        assert http_honeypot._running is False

    def test_health_check_not_running(self, http_honeypot):
        """Test health check when not running."""
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            http_honeypot.health_check()
        )
        assert result["service"] == "http_honeypot"
        assert result["running"] is False
        assert result["port"] == 8080

    def test_wordpress_headers(self, http_honeypot):
        """Test WordPress headers are returned correctly."""
        headers = http_honeypot._get_wordpress_headers()
        assert "Server" in headers
        assert "X-Powered-By" in headers
        assert "PHP" in headers["X-Powered-By"]

    def test_generate_wordpress_home(self, http_honeypot):
        """Test WordPress home page generation."""
        html = http_honeypot._generate_wordpress_home()
        assert "WordPress" in html or "Company Blog" in html
        assert "<!DOCTYPE html>" in html

    def test_generate_wp_login_page(self, http_honeypot):
        """Test WordPress login page generation."""
        html = http_honeypot._generate_wp_login_page()
        assert "wp-login.php" in html
        assert "Username" in html
        assert "Password" in html

    def test_generate_wp_login_with_error(self, http_honeypot):
        """Test WordPress login page with error message."""
        html = http_honeypot._generate_wp_login_page(error=True)
        assert "Error:" in html or "login_error" in html

    def test_generate_404_page(self, http_honeypot):
        """Test 404 page generation."""
        html = http_honeypot._generate_404_page("/nonexistent")
        assert "404" in html
        assert "<!DOCTYPE html>" in html


class TestAttackPatterns:
    """Tests for attack pattern detection."""

    def test_sql_injection_patterns_exist(self):
        """Test SQL injection patterns are defined."""
        assert "sql_injection" in ATTACK_PATTERNS
        assert len(ATTACK_PATTERNS["sql_injection"]) > 0

    def test_xss_patterns_exist(self):
        """Test XSS patterns are defined."""
        assert "xss" in ATTACK_PATTERNS
        assert len(ATTACK_PATTERNS["xss"]) > 0

    def test_path_traversal_patterns_exist(self):
        """Test path traversal patterns are defined."""
        assert "path_traversal" in ATTACK_PATTERNS
        assert len(ATTACK_PATTERNS["path_traversal"]) > 0

    def test_suspicious_paths_include_common_targets(self):
        """Test suspicious paths include common attack targets."""
        assert "/wp-admin" in SUSPICIOUS_PATHS
        assert "/.env" in SUSPICIOUS_PATHS
        assert "/phpmyadmin" in SUSPICIOUS_PATHS
