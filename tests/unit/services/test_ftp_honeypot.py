# tests/unit/services/test_ftp_honeypot.py
"""
Unit tests for FTP Honeypot service.
"""
import pytest
from unittest.mock import MagicMock

from tenebrinet.services.ftp.server import (
    FTPHoneypot,
    FTPClientHandler,
    FAKE_FILES,
)
from tenebrinet.core.config import FTPServiceConfig


@pytest.fixture
def ftp_config():
    """Create a test FTP configuration."""
    return FTPServiceConfig(
        enabled=True,
        port=2121,
        host="127.0.0.1",
        anonymous_allowed=True,
        timeout=30,
    )


@pytest.fixture
def ftp_honeypot(ftp_config):
    """Create a test FTP honeypot instance."""
    return FTPHoneypot(ftp_config)


class TestFTPHoneypot:
    """Tests for FTPHoneypot class."""

    def test_initialization(self, ftp_honeypot, ftp_config):
        """Test honeypot initializes with correct config."""
        assert ftp_honeypot.host == ftp_config.host
        assert ftp_honeypot.port == ftp_config.port
        assert ftp_honeypot.anonymous == ftp_config.anonymous_allowed
        assert ftp_honeypot._running is False

    def test_health_check_not_running(self, ftp_honeypot):
        """Test health check when not running."""
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            ftp_honeypot.health_check()
        )
        assert result["service"] == "ftp_honeypot"
        assert result["running"] is False
        assert result["port"] == 2121


class TestFakeFilesystem:
    """Tests for the fake filesystem."""

    def test_root_directory_exists(self):
        """Test root directory is defined."""
        assert "/" in FAKE_FILES
        assert len(FAKE_FILES["/"]) > 0

    def test_backup_directory_exists(self):
        """Test backup directory is defined."""
        assert "/backup" in FAKE_FILES
        files = [f["name"] for f in FAKE_FILES["/backup"]]
        assert "credentials.txt" in files
        assert "db_backup_2024.sql.gz" in files

    def test_public_html_directory_exists(self):
        """Test public_html directory is defined."""
        assert "/public_html" in FAKE_FILES
        files = [f["name"] for f in FAKE_FILES["/public_html"]]
        assert "wp-config.php" in files

    def test_fake_files_have_required_attributes(self):
        """Test all fake files have required attributes."""
        for path, files in FAKE_FILES.items():
            for f in files:
                assert "name" in f
                assert "type" in f
                assert "size" in f
                assert f["type"] in ("d", "-")


class TestFTPClientHandler:
    """Tests for FTPClientHandler."""

    def test_resolve_path_absolute(self, ftp_honeypot):
        """Test path resolution for absolute paths."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )
        handler.current_dir = "/"

        assert handler._resolve_path("/backup") == "/backup"
        assert handler._resolve_path("/public_html") == "/public_html"

    def test_resolve_path_relative(self, ftp_honeypot):
        """Test path resolution for relative paths."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )
        handler.current_dir = "/"

        assert handler._resolve_path("backup") == "/backup"

    def test_resolve_path_parent(self, ftp_honeypot):
        """Test path resolution with parent directory."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )
        handler.current_dir = "/backup"

        assert handler._resolve_path("..") == "/"

    def test_generate_listing(self, ftp_honeypot):
        """Test directory listing generation."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )

        listing = handler._generate_listing("/")
        assert len(listing) > 0
        assert any("backup" in line for line in listing)

    def test_get_fake_file_content_credentials(self, ftp_honeypot):
        """Test fake content for credentials file."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )

        content = handler._get_fake_file_content("credentials.txt")
        assert "admin" in content
        assert ":" in content

    def test_get_fake_file_content_config(self, ftp_honeypot):
        """Test fake content for config file."""
        handler = FTPClientHandler(
            MagicMock(), MagicMock(), ftp_honeypot
        )

        content = handler._get_fake_file_content("wp-config.php")
        assert "DB_PASSWORD" in content
        assert "<?php" in content
