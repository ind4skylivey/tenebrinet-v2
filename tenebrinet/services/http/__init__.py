# tenebrinet/services/http/__init__.py
"""
HTTP Honeypot service package.

Provides a fake web server simulating a vulnerable CMS
to capture web-based attacks and reconnaissance.
"""

from tenebrinet.services.http.server import HTTPHoneypot

__all__ = ["HTTPHoneypot"]
