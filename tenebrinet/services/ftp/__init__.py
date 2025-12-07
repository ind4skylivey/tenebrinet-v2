# tenebrinet/services/ftp/__init__.py
"""
FTP Honeypot service package.

Provides a fake FTP server for capturing credentials
and file transfer attempts.
"""

from tenebrinet.services.ftp.server import FTPHoneypot

__all__ = ["FTPHoneypot"]
