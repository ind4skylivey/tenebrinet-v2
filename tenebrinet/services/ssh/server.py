# tenebrinet/services/ssh/server.py
"""
SSH Honeypot Server implementation.

Provides a fake SSH server that captures credentials and simulates
a minimal shell environment for attacker interaction logging.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncssh
import structlog

from tenebrinet.core.config import SSHServiceConfig
from tenebrinet.core.database import AsyncSessionLocal
from tenebrinet.core.models import Attack, Credential, Session


logger = structlog.get_logger()


class SSHHoneypotServer(asyncssh.SSHServer):
    """
    SSH Server handler for the honeypot.

    Handles authentication attempts and session management.
    """

    def __init__(self, honeypot: "SSHHoneypot") -> None:
        self.honeypot = honeypot
        self.client_ip: Optional[str] = None
        self.attack_id: Optional[uuid.UUID] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a new connection is established."""
        peername = conn.get_extra_info("peername")
        self.client_ip = peername[0] if peername else "unknown"
        logger.info(
            "ssh_connection_established",
            client_ip=self.client_ip,
            port=self.honeypot.port,
        )

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost."""
        logger.info(
            "ssh_connection_closed",
            client_ip=self.client_ip,
            error=str(exc) if exc else None,
        )

    def begin_auth(self, username: str) -> bool:
        """
        Called when authentication begins.

        Returns True to allow authentication to proceed.
        """
        logger.debug(
            "ssh_auth_begin",
            client_ip=self.client_ip,
            username=username,
        )
        return True

    def password_auth_supported(self) -> bool:
        """Enable password authentication."""
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        """
        Validate password - always fails but logs the attempt.

        This captures the credentials attempted by attackers.
        """
        logger.warning(
            "ssh_credential_captured",
            client_ip=self.client_ip,
            username=username,
            password=password,
        )

        # Store the attack in the database
        await self._record_attack(username, password)

        # Always return True to allow the attacker to "login"
        # This lets us capture more information about their behavior
        return True

    async def _record_attack(self, username: str, password: str) -> None:
        """Record the attack attempt in the database."""
        try:
            async with AsyncSessionLocal() as session:
                # Create the attack record
                attack = Attack(
                    ip=self.client_ip or "unknown",
                    service="ssh",
                    threat_type="credential_attack",
                    payload={
                        "username": username,
                        "password_length": len(password),
                    },
                )
                session.add(attack)
                await session.flush()

                self.attack_id = attack.id

                # Create the credential record
                credential = Credential(
                    attack_id=attack.id,
                    username=username,
                    password=password,
                    success=True,  # We let them "succeed"
                )
                session.add(credential)

                await session.commit()
                logger.info(
                    "ssh_attack_recorded",
                    attack_id=str(attack.id),
                    client_ip=self.client_ip,
                )
        except Exception as e:
            logger.error(
                "ssh_attack_record_failed",
                error=str(e),
                client_ip=self.client_ip,
            )


class SSHHoneypotSession(asyncssh.SSHServerSession):
    """
    SSH Session handler that simulates a shell environment.
    """

    def __init__(self, server: SSHHoneypotServer) -> None:
        self.server = server
        self.commands: list = []
        self.session_id: Optional[uuid.UUID] = None
        self._chan: Optional[asyncssh.SSHServerChannel] = None

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        """Called when the session channel is opened."""
        self._chan = chan

    def shell_requested(self) -> bool:
        """Handle shell request."""
        logger.info(
            "ssh_shell_requested",
            client_ip=self.server.client_ip,
        )
        return True

    def session_started(self) -> None:
        """Called when the session starts."""
        asyncio.create_task(self._start_shell())

    async def _start_shell(self) -> None:
        """Start the fake shell interaction."""
        if not self._chan:
            return

        # Create session record in database
        await self._create_session_record()

        # Send fake banner
        banner = (
            "\r\n"
            "Welcome to Ubuntu 20.04.3 LTS "
            "(GNU/Linux 5.4.0-89-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
            "\r\n"
            "Last login: Mon Dec  2 14:23:45 2024 from 192.168.1.1\r\n"
        )
        self._chan.write(banner)

        # Show prompt
        self._send_prompt()

    def _send_prompt(self) -> None:
        """Send the fake shell prompt."""
        if self._chan:
            self._chan.write("root@honeypot:~# ")

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        """Handle data received from the client."""
        # Echo the character back
        if self._chan:
            self._chan.write(data)

        # Handle command input
        if data == "\r" or data == "\n":
            if self.commands:
                cmd = "".join(self.commands).strip()
                if cmd:
                    asyncio.create_task(self._handle_command(cmd))
                self.commands = []
            if self._chan:
                self._chan.write("\r\n")
                self._send_prompt()
        elif data == "\x7f":  # Backspace
            if self.commands:
                self.commands.pop()
                if self._chan:
                    self._chan.write("\b \b")
        elif data == "\x03":  # Ctrl+C
            if self._chan:
                self._chan.write("^C\r\n")
                self._send_prompt()
            self.commands = []
        elif data == "\x04":  # Ctrl+D (EOF)
            self.eof_received()
        else:
            self.commands.append(data)

    async def _handle_command(self, command: str) -> None:
        """Handle a command entered by the attacker."""
        logger.warning(
            "ssh_command_captured",
            client_ip=self.server.client_ip,
            command=command,
        )

        # Generate fake responses for common commands
        response = self._generate_fake_response(command)
        if response and self._chan:
            self._chan.write(response + "\r\n")

        # Update session with command
        await self._record_command(command)

    def _generate_fake_response(self, command: str) -> str:
        """Generate fake responses to common commands."""
        cmd_lower = command.lower().strip()
        cmd_base = cmd_lower.split()[0] if cmd_lower else ""

        fake_responses = {
            "whoami": "root",
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "pwd": "/root",
            "uname": "Linux",
            "uname -a": (
                "Linux honeypot 5.4.0-89-generic #100-Ubuntu SMP "
                "Fri Sep 24 14:50:10 UTC 2021 x86_64 GNU/Linux"
            ),
            "hostname": "honeypot",
            "uptime": (
                " 14:32:45 up 127 days, 3:42, 1 user, load average: "
                "0.00, 0.01, 0.05"
            ),
            "cat /etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            ),
            "ls": "Desktop  Documents  Downloads  Music  Pictures",
            "ls -la": (
                "total 32\n"
                "drwx------  5 root root 4096 Dec  2 14:23 .\n"
                "drwxr-xr-x 20 root root 4096 Nov 15 10:00 ..\n"
                "-rw-------  1 root root  220 Nov 15 10:00 .bash_logout\n"
                "-rw-------  1 root root 3771 Nov 15 10:00 .bashrc\n"
                "drwx------  2 root root 4096 Nov 15 10:00 .ssh"
            ),
            "w": (
                " 14:32:45 up 127 days, 1 user, load average: 0.00\n"
                "USER     TTY      FROM             LOGIN@   IDLE\n"
                "root     pts/0    192.168.1.100    14:32    0.00s"
            ),
            "exit": "",
            "logout": "",
        }

        # Check for exact match first
        if cmd_lower in fake_responses:
            if cmd_lower in ("exit", "logout"):
                self.eof_received()
                return ""
            return fake_responses[cmd_lower]

        # Check base command
        if cmd_base in fake_responses:
            return fake_responses[cmd_base]

        # Default: command not found
        if cmd_base and cmd_base not in ("cd", "export", "source", "."):
            return f"-bash: {cmd_base}: command not found"

        return ""

    async def _create_session_record(self) -> None:
        """Create a session record in the database."""
        if not self.server.attack_id:
            return

        try:
            async with AsyncSessionLocal() as db_session:
                session = Session(
                    attack_id=self.server.attack_id,
                    commands=[],
                )
                db_session.add(session)
                await db_session.commit()
                self.session_id = session.id
                logger.info(
                    "ssh_session_created",
                    session_id=str(session.id),
                    attack_id=str(self.server.attack_id),
                )
        except Exception as e:
            logger.error("ssh_session_create_failed", error=str(e))

    async def _record_command(self, command: str) -> None:
        """Record a command in the session."""
        if not self.session_id:
            return

        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.get(Session, self.session_id)
                if result:
                    commands = result.commands or []
                    commands.append({
                        "cmd": command,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    result.commands = commands
                    await db_session.commit()
        except Exception as e:
            logger.error("ssh_command_record_failed", error=str(e))

    def eof_received(self) -> bool:
        """Handle EOF (session end)."""
        logger.info(
            "ssh_session_ended",
            client_ip=self.server.client_ip,
            session_id=str(self.session_id) if self.session_id else None,
        )

        # Update session end time
        asyncio.create_task(self._close_session())

        if self._chan:
            self._chan.write("\r\nlogout\r\n")
            self._chan.close()
        return True

    async def _close_session(self) -> None:
        """Close the session and record end time."""
        if not self.session_id:
            return

        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.get(Session, self.session_id)
                if result:
                    result.end_time = datetime.now(timezone.utc)
                    await db_session.commit()
        except Exception as e:
            logger.error("ssh_session_close_failed", error=str(e))


class SSHHoneypot:
    """
    Main SSH Honeypot service.

    Manages the SSH server lifecycle and configuration.
    """

    def __init__(self, config: SSHServiceConfig) -> None:
        self.config = config
        self.host = config.host
        self.port = config.port
        self.banner = config.banner
        self.server: Optional[asyncssh.SSHAcceptor] = None
        self._running = False

    async def start(self) -> None:
        """Start the SSH honeypot server."""
        if self._running:
            logger.warning("ssh_honeypot_already_running")
            return

        logger.info(
            "ssh_honeypot_starting",
            host=self.host,
            port=self.port,
        )

        try:
            # Generate or load host key
            host_key = asyncssh.generate_private_key("ssh-rsa", 2048)

            self.server = await asyncssh.create_server(
                lambda: SSHHoneypotServer(self),
                self.host,
                self.port,
                server_host_keys=[host_key],
                process_factory=self._create_session,
                server_version=f"SSH-2.0-{self.banner}",
            )

            self._running = True
            logger.info(
                "ssh_honeypot_started",
                host=self.host,
                port=self.port,
            )
        except Exception as e:
            logger.error(
                "ssh_honeypot_start_failed",
                error=str(e),
                exc_info=True,
            )
            raise

    def _create_session(self, stdin, stdout, stderr):
        """Create a session handler - not used with session_factory."""
        pass

    async def stop(self) -> None:
        """Stop the SSH honeypot server."""
        if not self._running:
            logger.warning("ssh_honeypot_not_running")
            return

        logger.info("ssh_honeypot_stopping")

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self._running = False
        logger.info("ssh_honeypot_stopped")

    async def health_check(self) -> dict:
        """Check if the SSH honeypot is healthy."""
        return {
            "service": "ssh_honeypot",
            "running": self._running,
            "host": self.host,
            "port": self.port,
        }
