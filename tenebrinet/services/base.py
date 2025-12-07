# tenebrinet/services/base.py
from abc import ABC, abstractmethod
from typing import Any
import asyncio
import structlog

logger = structlog.get_logger()

class BaseHoneypotService(ABC):
    """Abstract base class for all honeypot services in TenebriNET.

    This class defines the common interface and lifecycle management for
    all honeypot services, ensuring consistency and reusability.
    """

    def __init__(
        self,
        name: str,
        port: int,
        host: str = "0.0.0.0",
        # TODO: Add rate_limiter_client: RedisClient | None = None later for rate limiting
    ) -> None:
        """Initializes the BaseHoneypotService.

        Args:
            name: The name of the honeypot service (e.g., "ssh", "http").
            port: The port number the service will listen on.
            host: The host address the service will bind to. Defaults to "0.0.0.0".
        """
        self.name = name
        self.port = port
        self.host = host
        self.server: asyncio.Server | None = None
        self._running = False
        logger.info(f"{self.name}_service_initialized", name=self.name, port=self.port, host=self.host)

    async def start(self) -> None:
        """Starts the honeypot service.

        Binds the service to the specified host and port, and begins listening
        for incoming connections.
        """
        if self._running:
            logger.warning(f"{self.name}_service_already_running", name=self.name)
            return

        logger.info(f"{self.name}_service_starting", name=self.name, port=self.port, host=self.host)
        try:
            self.server = await asyncio.start_server(
                self.handle_connection,
                self.host,
                self.port
            )
            self._running = True
            addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
            logger.info(f"{self.name}_service_started", name=self.name, port=self.port, host=self.host, addrs=addrs)
        except Exception as e:
            logger.error(f"{self.name}_service_start_failed", name=self.name, port=self.port, error=str(e), exc_info=True)
            raise

    async def stop(self) -> None:
        """Stops the honeypot service.

        Closes all open connections and releases the listening socket.
        """
        if not self._running:
            logger.warning(f"{self.name}_service_not_running", name=self.name)
            return

        logger.info(f"{self.name}_service_stopping", name=self.name, port=self.port)
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False
        logger.info(f"{self.name}_service_stopped", name=self.name, port=self.port)

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """Abstract method to handle an incoming client connection.

        Concrete honeypot service implementations must provide their logic
        for interacting with clients in this method.

        Args:
            reader: The StreamReader object for reading data from the client.
            writer: The StreamWriter object for writing data to the client.
        """
        pass

    async def health_check(self) -> dict[str, Any]:
        """Performs a health check on the service.

        Returns:
            A dictionary containing the service's current health status.
        """
        status = {
            "service": self.name,
            "running": self._running,
            "port": self.port,
            "host": self.host,
            "connections": len(self.server.sockets) if self.server else 0,
        }
        logger.debug(f"{self.name}_health_check", status=status)
        return status
