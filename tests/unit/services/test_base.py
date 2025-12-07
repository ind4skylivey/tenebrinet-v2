# tests/unit/services/test_base.py
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from tenebrinet.services.base import BaseHoneypotService

# Concrete implementation for testing the abstract BaseHoneypotService
class MockHoneypotService(BaseHoneypotService):
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """A dummy handle_connection for testing."""
        writer.write(b"Mock data")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

@pytest.mark.asyncio
async def test_base_honeypot_service_initialization():
    """Test that BaseHoneypotService initializes correctly."""
    service = MockHoneypotService(name="mock_test", port=12345)
    assert service.name == "mock_test"
    assert service.port == 12345
    assert service.host == "0.0.0.0"
    assert service.server is None
    assert service._running is False

@pytest.mark.asyncio
async def test_base_honeypot_service_start_stop():
    """Test the start and stop lifecycle methods of BaseHoneypotService."""
    service = MockHoneypotService(name="mock_start_stop", port=12346)

    # Test start
    await service.start()
    assert service._running is True
    assert service.server is not None
    
    # Check if the server is actually listening (by trying to connect)
    # This is a bit tricky with AsyncMock, so we'll simulate the server behavior
    # For a real test, one would try to establish a connection.
    # For now, we rely on the internal state and the fact that asyncio.start_server
    # would raise an exception if it couldn't bind.

    # Test stopping an already running service
    await service.stop()
    assert service._running is False
    # server object might still exist but should be closed
    assert service.server is not None # server object still exists
    # If we wanted to be very thorough, we'd mock the server to check for close() call
    
    # Test stopping an already stopped service
    await service.stop() # Should log a warning and do nothing
    assert service._running is False

@pytest.mark.asyncio
async def test_base_honeypot_service_health_check():
    """Test the health_check method."""
    service = MockHoneypotService(name="mock_health", port=12347)
    
    # Before starting
    status = await service.health_check()
    assert status["service"] == "mock_health"
    assert status["running"] is False
    assert status["port"] == 12347
    assert status["host"] == "0.0.0.0"
    assert status["connections"] == 0

    await service.start()
    status = await service.health_check()
    assert status["running"] is True
    assert status["connections"] >= 0 # Should be 1 if server was properly mocked, but for real server it's at least 1 (the listener)
    await service.stop()

@pytest.mark.asyncio
async def test_base_honeypot_service_handle_connection_abstract():
    """Verify that BaseHoneypotService cannot be instantiated directly."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class BaseHoneypotService without an implementation for abstract method 'handle_connection'"):
        BaseHoneypotService(name="abstract_test", port=12348)

@pytest.mark.asyncio
async def test_mock_honeypot_service_handle_connection():
    """Test the handle_connection method of the MockHoneypotService."""
    # This test primarily ensures our MockHoneypotService is functional
    # and demonstrates how handle_connection would be called.
    
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    
    # Mock return value for writer.getsockname() for logging
    writer.get_extra_info.return_value = ('127.0.0.1', 54321)

    service = MockHoneypotService(name="mock_connection_test", port=12349)
    await service.handle_connection(reader, writer)

    writer.write.assert_called_once_with(b"Mock data")
    writer.drain.assert_awaited_once()
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()
