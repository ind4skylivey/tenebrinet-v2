# tenebrinet/services/ftp/server.py
"""
FTP Honeypot Server implementation.

Provides a fake FTP server that captures credentials and
logs file transfer attempts and commands.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional
import uuid

import structlog

from tenebrinet.core.config import FTPServiceConfig
from tenebrinet.core.database import AsyncSessionLocal
from tenebrinet.core.models import Attack, Credential, Session


logger = structlog.get_logger()


# Fake directory structure
FAKE_FILES = {
    "/": [
        {"name": ".", "type": "d", "size": 4096},
        {"name": "..", "type": "d", "size": 4096},
        {"name": "backup", "type": "d", "size": 4096},
        {"name": "public_html", "type": "d", "size": 4096},
        {"name": "logs", "type": "d", "size": 4096},
        {"name": ".htaccess", "type": "-", "size": 235},
        {"name": "config.php", "type": "-", "size": 1842},
    ],
    "/backup": [
        {"name": ".", "type": "d", "size": 4096},
        {"name": "..", "type": "d", "size": 4096},
        {"name": "db_backup_2024.sql.gz", "type": "-", "size": 15728640},
        {"name": "site_backup.tar.gz", "type": "-", "size": 52428800},
        {"name": "credentials.txt", "type": "-", "size": 512},
    ],
    "/public_html": [
        {"name": ".", "type": "d", "size": 4096},
        {"name": "..", "type": "d", "size": 4096},
        {"name": "index.php", "type": "-", "size": 4523},
        {"name": "wp-config.php", "type": "-", "size": 2841},
        {"name": "wp-content", "type": "d", "size": 4096},
    ],
    "/logs": [
        {"name": ".", "type": "d", "size": 4096},
        {"name": "..", "type": "d", "size": 4096},
        {"name": "access.log", "type": "-", "size": 1048576},
        {"name": "error.log", "type": "-", "size": 524288},
    ],
}


class FTPClientHandler:
    """
    Handles a single FTP client connection.

    Implements the FTP protocol commands and captures all activity.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        honeypot: "FTPHoneypot",
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.honeypot = honeypot
        self.client_ip: str = "unknown"
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated: bool = False
        self.current_dir: str = "/"
        self.attack_id: Optional[uuid.UUID] = None
        self.session_id: Optional[uuid.UUID] = None
        self.commands: list = []
        self.data_writer: Optional[asyncio.StreamWriter] = None
        self.passive_server: Optional[asyncio.Server] = None
        self.rename_from: Optional[str] = None

    async def handle(self) -> None:
        """Handle the FTP client connection."""
        try:
            peername = self.writer.get_extra_info("peername")
            self.client_ip = peername[0] if peername else "unknown"

            logger.info(
                "ftp_connection_established",
                client_ip=self.client_ip,
            )

            # Send welcome banner
            await self._send_response(
                220, "Welcome to FTP server (vsFTPd 3.0.3)"
            )

            # Process commands
            while True:
                try:
                    data = await asyncio.wait_for(
                        self.reader.readline(),
                        timeout=self.honeypot.config.timeout or 30,
                    )
                except asyncio.TimeoutError:
                    await self._send_response(421, "Timeout.")
                    break

                if not data:
                    break

                line = data.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                await self._process_command(line)

        except ConnectionResetError:
            logger.debug(
                "ftp_connection_reset",
                client_ip=self.client_ip,
            )
        except Exception as e:
            logger.error(
                "ftp_handler_error",
                client_ip=self.client_ip,
                error=str(e),
            )
        finally:
            await self._close_session()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def _send_response(self, code: int, message: str) -> None:
        """Send an FTP response to the client."""
        response = f"{code} {message}\r\n"
        self.writer.write(response.encode("utf-8"))
        await self.writer.drain()

    async def _send_multiline(self, code: int, lines: list) -> None:
        """Send a multiline FTP response."""
        for i, line in enumerate(lines):
            if i == len(lines) - 1:
                response = f"{code} {line}\r\n"
            else:
                response = f"{code}-{line}\r\n"
            self.writer.write(response.encode("utf-8"))
        await self.writer.drain()

    async def _process_command(self, line: str) -> None:
        """Process an FTP command."""
        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        logger.debug(
            "ftp_command_received",
            client_ip=self.client_ip,
            command=cmd,
            argument=arg if cmd != "PASS" else "***",
        )

        # Record command
        self.commands.append({
            "cmd": cmd,
            "arg": arg if cmd != "PASS" else "***",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Command handlers
        handlers = {
            "USER": self._cmd_user,
            "PASS": self._cmd_pass,
            "SYST": self._cmd_syst,
            "FEAT": self._cmd_feat,
            "PWD": self._cmd_pwd,
            "CWD": self._cmd_cwd,
            "CDUP": self._cmd_cdup,
            "TYPE": self._cmd_type,
            "PASV": self._cmd_pasv,
            "LIST": self._cmd_list,
            "NLST": self._cmd_nlst,
            "RETR": self._cmd_retr,
            "STOR": self._cmd_stor,
            "DELE": self._cmd_dele,
            "MKD": self._cmd_mkd,
            "RMD": self._cmd_rmd,
            "RNFR": self._cmd_rnfr,
            "RNTO": self._cmd_rnto,
            "SIZE": self._cmd_size,
            "QUIT": self._cmd_quit,
            "NOOP": self._cmd_noop,
            "OPTS": self._cmd_opts,
            "PORT": self._cmd_port,
        }

        handler = handlers.get(cmd, self._cmd_unknown)
        await handler(arg)

    # --- Authentication Commands ---

    async def _cmd_user(self, username: str) -> None:
        """Handle USER command."""
        self.username = username
        self.authenticated = False

        if username.lower() == "anonymous" and self.honeypot.anonymous:
            self.authenticated = True
            await self._record_attack()
            await self._send_response(
                230, "Anonymous login ok, proceed."
            )
        else:
            await self._send_response(
                331, "Please specify the password."
            )

    async def _cmd_pass(self, password: str) -> None:
        """Handle PASS command."""
        self.password = password

        if not self.username:
            await self._send_response(503, "Login with USER first.")
            return

        # Log the credential attempt
        await self._record_attack()
        await self._record_credential()

        # Always allow login to capture more behavior
        self.authenticated = True
        await self._send_response(230, "Login successful.")

        logger.warning(
            "ftp_credential_captured",
            client_ip=self.client_ip,
            username=self.username,
        )

    # --- System Commands ---

    async def _cmd_syst(self, arg: str) -> None:
        """Handle SYST command."""
        await self._send_response(215, "UNIX Type: L8")

    async def _cmd_feat(self, arg: str) -> None:
        """Handle FEAT command."""
        features = [
            "Features:",
            " UTF8",
            " PASV",
            " SIZE",
            " MDTM",
            "End",
        ]
        await self._send_multiline(211, features)

    async def _cmd_opts(self, arg: str) -> None:
        """Handle OPTS command."""
        if arg.upper().startswith("UTF8"):
            await self._send_response(200, "UTF8 set to on")
        else:
            await self._send_response(501, "Option not understood")

    async def _cmd_noop(self, arg: str) -> None:
        """Handle NOOP command."""
        await self._send_response(200, "NOOP ok.")

    # --- Directory Commands ---

    async def _cmd_pwd(self, arg: str) -> None:
        """Handle PWD command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return
        await self._send_response(
            257, f'"{self.current_dir}" is the current directory'
        )

    async def _cmd_cwd(self, path: str) -> None:
        """Handle CWD command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        new_path = self._resolve_path(path)
        if new_path in FAKE_FILES:
            self.current_dir = new_path
            await self._send_response(
                250, "Directory successfully changed."
            )
        else:
            await self._send_response(
                550, "Failed to change directory."
            )

    async def _cmd_cdup(self, arg: str) -> None:
        """Handle CDUP command."""
        await self._cmd_cwd("..")

    async def _cmd_mkd(self, path: str) -> None:
        """Handle MKD command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_mkdir_attempt",
            client_ip=self.client_ip,
            path=path,
        )
        await self._send_response(
            257, f'"{path}" created'
        )

    async def _cmd_rmd(self, path: str) -> None:
        """Handle RMD command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_rmdir_attempt",
            client_ip=self.client_ip,
            path=path,
        )
        await self._send_response(550, "Remove directory failed.")

    # --- File Commands ---

    async def _cmd_type(self, type_code: str) -> None:
        """Handle TYPE command."""
        if type_code.upper() in ("A", "I"):
            await self._send_response(
                200, f"Switching to {type_code.upper()} mode."
            )
        else:
            await self._send_response(504, "Type not implemented.")

    async def _cmd_size(self, path: str) -> None:
        """Handle SIZE command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        full_path = self._resolve_path(path)
        dir_path = "/".join(full_path.rsplit("/", 1)[:-1]) or "/"
        filename = full_path.rsplit("/", 1)[-1]

        files = FAKE_FILES.get(dir_path, [])
        for f in files:
            if f["name"] == filename:
                await self._send_response(213, str(f["size"]))
                return

        await self._send_response(550, "Could not get file size.")

    async def _cmd_retr(self, path: str) -> None:
        """Handle RETR (download) command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_download_attempt",
            client_ip=self.client_ip,
            path=path,
        )

        if not self.data_writer:
            await self._send_response(
                425, "Use PASV or PORT first."
            )
            return

        await self._send_response(
            150, "Opening BINARY mode data connection."
        )

        # Send fake file content
        fake_content = self._get_fake_file_content(path)
        try:
            self.data_writer.write(fake_content.encode("utf-8"))
            await self.data_writer.drain()
        finally:
            self.data_writer.close()
            self.data_writer = None

        await self._send_response(226, "Transfer complete.")

    async def _cmd_stor(self, path: str) -> None:
        """Handle STOR (upload) command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_upload_attempt",
            client_ip=self.client_ip,
            path=path,
        )

        if not self.data_writer:
            await self._send_response(425, "Use PASV or PORT first.")
            return

        await self._send_response(
            150, "Ok to send data."
        )

        # Read and discard the uploaded data
        try:
            # Read from passive connection reader
            pass
        finally:
            if self.data_writer:
                self.data_writer.close()
                self.data_writer = None

        await self._send_response(226, "Transfer complete.")

    async def _cmd_dele(self, path: str) -> None:
        """Handle DELE command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_delete_attempt",
            client_ip=self.client_ip,
            path=path,
        )
        await self._send_response(550, "Delete operation failed.")

    async def _cmd_rnfr(self, path: str) -> None:
        """Handle RNFR (rename from) command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return
        self.rename_from = path
        await self._send_response(350, "Ready for destination name")

    async def _cmd_rnto(self, path: str) -> None:
        """Handle RNTO (rename to) command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        logger.warning(
            "ftp_rename_attempt",
            client_ip=self.client_ip,
            from_path=self.rename_from,
            to_path=path,
        )
        self.rename_from = None
        await self._send_response(550, "Rename failed.")

    # --- Data Transfer Commands ---

    async def _cmd_pasv(self, arg: str) -> None:
        """Handle PASV command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        # Create a passive data connection server
        try:
            self.passive_server = await asyncio.start_server(
                self._handle_passive_connection,
                "0.0.0.0",
                0,  # Let OS pick a port
            )
            addr = self.passive_server.sockets[0].getsockname()
            ip = self.honeypot.host
            if ip == "0.0.0.0":
                ip = "127.0.0.1"
            port = addr[1]

            # Format: h1,h2,h3,h4,p1,p2
            ip_parts = ip.replace(".", ",")
            p1, p2 = port // 256, port % 256

            await self._send_response(
                227, f"Entering Passive Mode ({ip_parts},{p1},{p2})."
            )
        except Exception as e:
            logger.error("ftp_pasv_failed", error=str(e))
            await self._send_response(
                425, "Cannot enter passive mode."
            )

    async def _cmd_port(self, arg: str) -> None:
        """Handle PORT command (active mode)."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        # We don't support active mode in the honeypot
        await self._send_response(
            200, "PORT command successful. Use PASV instead."
        )

    async def _handle_passive_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming passive data connection."""
        self.data_writer = writer

    async def _cmd_list(self, path: str) -> None:
        """Handle LIST command."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        if not self.data_writer:
            # Wait a moment for passive connection
            await asyncio.sleep(0.5)
            if not self.data_writer:
                await self._send_response(
                    425, "Use PASV or PORT first."
                )
                return

        await self._send_response(
            150, "Here comes the directory listing."
        )

        # Generate directory listing
        target_dir = self._resolve_path(path) if path else self.current_dir
        listing = self._generate_listing(target_dir)

        try:
            for line in listing:
                self.data_writer.write((line + "\r\n").encode("utf-8"))
            await self.data_writer.drain()
        finally:
            self.data_writer.close()
            self.data_writer = None
            if self.passive_server:
                self.passive_server.close()
                self.passive_server = None

        await self._send_response(226, "Directory send OK.")

    async def _cmd_nlst(self, path: str) -> None:
        """Handle NLST command (name list)."""
        if not self.authenticated:
            await self._send_response(530, "Please login first.")
            return

        if not self.data_writer:
            await self._send_response(425, "Use PASV or PORT first.")
            return

        await self._send_response(
            150, "Here comes the directory listing."
        )

        target_dir = self._resolve_path(path) if path else self.current_dir
        files = FAKE_FILES.get(target_dir, [])

        try:
            for f in files:
                if f["name"] not in (".", ".."):
                    line = f["name"] + "\r\n"
                    self.data_writer.write(line.encode("utf-8"))
            await self.data_writer.drain()
        finally:
            self.data_writer.close()
            self.data_writer = None

        await self._send_response(226, "Directory send OK.")

    async def _cmd_quit(self, arg: str) -> None:
        """Handle QUIT command."""
        await self._send_response(221, "Goodbye.")

    async def _cmd_unknown(self, arg: str) -> None:
        """Handle unknown commands."""
        await self._send_response(502, "Command not implemented.")

    # --- Helper Methods ---

    def _resolve_path(self, path: str) -> str:
        """Resolve a path relative to current directory."""
        if not path:
            return self.current_dir

        if path.startswith("/"):
            result = path
        else:
            if self.current_dir == "/":
                result = "/" + path
            else:
                result = self.current_dir + "/" + path

        # Handle . and ..
        parts = result.split("/")
        resolved = []
        for part in parts:
            if part == "..":
                if resolved:
                    resolved.pop()
            elif part and part != ".":
                resolved.append(part)

        return "/" + "/".join(resolved) if resolved else "/"

    def _generate_listing(self, path: str) -> list:
        """Generate a Unix-style directory listing."""
        files = FAKE_FILES.get(path, [])
        lines = []

        for f in files:
            ftype = "d" if f["type"] == "d" else "-"
            perms = "rwxr-xr-x" if f["type"] == "d" else "rw-r--r--"
            size = f["size"]
            name = f["name"]
            date = "Dec  5 12:00"

            line = f"{ftype}{perms}   1 ftp      ftp  {size:>10} {date} {name}"
            lines.append(line)

        return lines

    def _get_fake_file_content(self, filename: str) -> str:
        """Return fake content for requested files."""
        lower = filename.lower()

        if "passwd" in lower or "credentials" in lower:
            return (
                "# Credentials backup\n"
                "admin:admin123\n"
                "root:toor\n"
                "ftpuser:ftp@2024!\n"
                "backup:b4ckup_p4ss\n"
            )
        elif "config" in lower or "wp-config" in lower:
            return (
                "<?php\n"
                "define('DB_NAME', 'wordpress');\n"
                "define('DB_USER', 'wp_admin');\n"
                "define('DB_PASSWORD', 'S3cr3t_DB_P4ss!');\n"
                "define('DB_HOST', 'localhost');\n"
                "?>\n"
            )
        elif ".sql" in lower:
            return (
                "-- MySQL dump\n"
                "-- Database: wordpress\n"
                "CREATE TABLE users (id INT, username VARCHAR(255));\n"
                "INSERT INTO users VALUES (1, 'admin');\n"
            )
        elif ".htaccess" in lower:
            return (
                "RewriteEngine On\n"
                "RewriteRule ^admin /login.php [L]\n"
            )
        else:
            return f"Content of {filename}\n"

    # --- Database Recording ---

    async def _record_attack(self) -> None:
        """Record the attack in the database."""
        try:
            async with AsyncSessionLocal() as session:
                attack = Attack(
                    ip=self.client_ip,
                    service="ftp",
                    threat_type="credential_attack",
                    payload={
                        "username": self.username,
                        "anonymous": self.username == "anonymous",
                    },
                )
                session.add(attack)
                await session.flush()
                self.attack_id = attack.id

                # Create session record
                sess = Session(
                    attack_id=attack.id,
                    commands=self.commands,
                )
                session.add(sess)
                await session.flush()
                self.session_id = sess.id

                await session.commit()
                logger.info(
                    "ftp_attack_recorded",
                    attack_id=str(attack.id),
                    client_ip=self.client_ip,
                )
        except Exception as e:
            logger.error("ftp_attack_record_failed", error=str(e))

    async def _record_credential(self) -> None:
        """Record captured credentials."""
        if not self.attack_id:
            return

        try:
            async with AsyncSessionLocal() as session:
                credential = Credential(
                    attack_id=self.attack_id,
                    username=self.username or "",
                    password=self.password or "",
                    success=True,
                )
                session.add(credential)
                await session.commit()
        except Exception as e:
            logger.error("ftp_credential_record_failed", error=str(e))

    async def _close_session(self) -> None:
        """Close and update the session."""
        if not self.session_id:
            return

        try:
            async with AsyncSessionLocal() as session:
                result = await session.get(Session, self.session_id)
                if result:
                    result.end_time = datetime.now(timezone.utc)
                    result.commands = self.commands
                    await session.commit()
        except Exception as e:
            logger.error("ftp_session_close_failed", error=str(e))

        if self.passive_server:
            self.passive_server.close()

        logger.info(
            "ftp_connection_closed",
            client_ip=self.client_ip,
            commands_count=len(self.commands),
        )


class FTPHoneypot:
    """
    FTP Honeypot service.

    Manages the FTP server lifecycle and configuration.
    """

    def __init__(self, config: FTPServiceConfig) -> None:
        self.config = config
        self.host = config.host
        self.port = config.port
        self.anonymous = config.anonymous_allowed
        self.server: Optional[asyncio.Server] = None
        self._running = False

    async def start(self) -> None:
        """Start the FTP honeypot server."""
        if self._running:
            logger.warning("ftp_honeypot_already_running")
            return

        logger.info(
            "ftp_honeypot_starting",
            host=self.host,
            port=self.port,
            anonymous=self.anonymous,
        )

        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.port,
            )

            self._running = True
            logger.info(
                "ftp_honeypot_started",
                host=self.host,
                port=self.port,
            )
        except Exception as e:
            logger.error(
                "ftp_honeypot_start_failed",
                error=str(e),
                exc_info=True,
            )
            raise

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new FTP client connection."""
        handler = FTPClientHandler(reader, writer, self)
        await handler.handle()

    async def stop(self) -> None:
        """Stop the FTP honeypot server."""
        if not self._running:
            logger.warning("ftp_honeypot_not_running")
            return

        logger.info("ftp_honeypot_stopping")

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self._running = False
        logger.info("ftp_honeypot_stopped")

    async def health_check(self) -> dict:
        """Check if the FTP honeypot is healthy."""
        return {
            "service": "ftp_honeypot",
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "anonymous_allowed": self.anonymous,
        }
