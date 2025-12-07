# tests/conftest.py
"""
Pytest configuration and shared fixtures for TenebriNET tests.
"""
import sys
from pathlib import Path

import pytest

# Ensure the project root is in the path so imports work correctly
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def project_root_path() -> Path:
    """Return the project root directory."""
    return project_root


@pytest.fixture
def sample_attack_data() -> dict:
    """Provide sample attack data for testing."""
    return {
        "ip": "192.168.1.100",
        "service": "ssh",
        "payload": {"username": "root", "password": "admin123"},
        "threat_type": "brute_force",
        "confidence": 0.95,
        "country": "US",
        "asn": 12345,
    }


@pytest.fixture
def sample_config_dict() -> dict:
    """Provide sample configuration dictionary for testing."""
    return {
        "services": {
            "ssh": {
                "enabled": True,
                "port": 2222,
                "host": "0.0.0.0",
                "banner": "OpenSSH_Test",
                "max_connections": 100,
                "timeout": 30,
            },
            "http": {
                "enabled": True,
                "port": 8080,
                "host": "0.0.0.0",
                "fake_cms": "WordPress",
                "serve_files": True,
            },
            "ftp": {
                "enabled": False,
                "port": 2121,
                "host": "0.0.0.0",
                "anonymous_allowed": False,
            },
        },
        "database": {
            "url": "postgresql+asyncpg://test:test@localhost/test_db",
            "pool_size": 5,
            "max_overflow": 10,
            "echo": False,
        },
        "redis": {
            "url": "redis://localhost:6379/0",
        },
        "ml": {
            "model_path": "data/models/test.joblib",
            "retrain_interval": "24h",
            "confidence_threshold": 0.7,
            "features": ["feature1", "feature2"],
        },
        "threat_intel": {
            "abuseipdb": {
                "enabled": True,
                "api_key": "test_key",
                "check_on_connect": True,
            },
            "virustotal": {
                "enabled": False,
                "api_key": None,
            },
        },
        "logging": {
            "level": "DEBUG",
            "format": "json",
            "output": "data/logs/test.log",
            "rotation": "100 MB",
        },
    }
