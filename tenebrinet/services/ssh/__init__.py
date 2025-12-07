# tenebrinet/services/ssh/__init__.py
"""
SSH Honeypot service package.

Provides a fake SSH server for capturing credentials and
recording attacker behavior.
"""

from tenebrinet.services.ssh.server import SSHHoneypot, SSHHoneypotServer

__all__ = ["SSHHoneypot", "SSHHoneypotServer"]
