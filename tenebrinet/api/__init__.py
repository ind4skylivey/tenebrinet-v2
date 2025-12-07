# tenebrinet/api/__init__.py
"""
TenebriNET REST API package.

Provides FastAPI-based REST endpoints for accessing honeypot data.
"""

from tenebrinet.api.main import app, create_app

__all__ = ["app", "create_app"]
