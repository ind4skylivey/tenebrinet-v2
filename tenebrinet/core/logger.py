# tenebrinet/core/logger.py
"""
Structured logging configuration for TenebriNET.

Provides a structured logging setup using structlog with support
for JSON and console output formats, with rotating file handlers.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import structlog
from structlog.stdlib import ProcessorFormatter


def configure_logger(
    log_level: str = "INFO",
    log_format: str = "json",
    log_output_path: str = "data/logs/tenebrinet.log",
    log_rotation_mb: int = 100,
) -> None:
    """
    Configure the structlog-based logger for TenebriNET.

    Args:
        log_level: Minimum logging level
            (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format - "json" for structured logs,
            "console" for dev.
        log_output_path: File path for log output.
        log_rotation_mb: Maximum size in MB before log rotation.
    """
    # Clear existing handlers to prevent duplicates during re-configuration
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure structlog processors for event dict enrichment
    structlog.configure(
        processors=[
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.CallsiteParameterAdder(
                {
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.LINENO,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.PROCESS,
                    structlog.processors.CallsiteParameter.THREAD,
                    structlog.processors.CallsiteParameter.THREAD_NAME,
                }
            ),
            ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Select final rendering processor based on format
    final_rendering_processors: list = []
    if log_format == "json":
        final_rendering_processors.append(structlog.processors.JSONRenderer())
    else:
        final_rendering_processors.append(structlog.dev.ConsoleRenderer())

    # Create the formatter with structlog processors
    formatter = ProcessorFormatter(
        fmt="%(message)s",
        processors=final_rendering_processors,
    )

    # Ensure log directory exists
    log_dir = os.path.dirname(log_output_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_output_path,
        maxBytes=log_rotation_mb * 1024 * 1024,
        backupCount=5,
        encoding="utf8",
    )
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Configure root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.setLevel(log_level.upper())

    # Suppress noise from third-party libraries
    logging.getLogger("uvicorn").propagate = False
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("asyncio").propagate = False
    logging.getLogger("sqlalchemy").propagate = False
