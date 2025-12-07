# tenebrinet/cli.py
"""
Command-line interface for TenebriNET.

Provides CLI commands for starting the honeypot services, managing
configuration, and monitoring system health.
"""
import asyncio

import click
import structlog
import uvicorn

from tenebrinet import __version__
from tenebrinet.core.config import load_config
from tenebrinet.core.database import init_db
from tenebrinet.core.logger import configure_logger


logger = structlog.get_logger()


@click.group()
@click.version_option(version=__version__, prog_name="TenebriNET")
def main() -> None:
    """
    TenebriNET - Intelligent Honeypot Infrastructure.

    An ML-powered threat intelligence system for security researchers.
    """
    pass


@main.command()
@click.option(
    "--config",
    "-c",
    default="config/honeypot.yml",
    help="Path to configuration file.",
    type=click.Path(exists=True),
)
@click.option(
    "--log-level",
    "-l",
    default="INFO",
    help="Logging level.",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        case_sensitive=False,
    ),
)
def start(config: str, log_level: str) -> None:
    """Start all TenebriNET honeypot services."""
    try:
        # Load configuration
        cfg = load_config(config)

        # Configure logging
        configure_logger(
            log_level=log_level,
            log_format=cfg.logging.format,
            log_output_path=cfg.logging.output,
        )

        logger.info(
            "tenebrinet_starting",
            version=__version__,
            config_path=config,
        )

        click.echo(f"🕸️  TenebriNET v{__version__}")
        click.echo(f"📁 Config: {config}")
        click.echo("🚀 Starting honeypot services...")

        # Run all services
        asyncio.run(_run_services(cfg))

    except FileNotFoundError as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        raise SystemExit(1)
    except KeyboardInterrupt:
        click.echo("\n👋 Shutting down...")


async def _run_services(cfg) -> None:
    """Run all honeypot services."""
    from tenebrinet.services.http import HTTPHoneypot
    from tenebrinet.services.ssh import SSHHoneypot

    # Initialize database
    await init_db()
    logger.info("database_initialized")

    services = []

    # Start SSH honeypot if enabled
    if cfg.services.ssh.enabled:
        ssh_honeypot = SSHHoneypot(cfg.services.ssh)
        await ssh_honeypot.start()
        services.append(ssh_honeypot)
        click.echo(
            f"   🔐 SSH Honeypot: listening on "
            f"{cfg.services.ssh.host}:{cfg.services.ssh.port}"
        )

    # Start HTTP honeypot if enabled
    if cfg.services.http.enabled:
        http_honeypot = HTTPHoneypot(cfg.services.http)
        await http_honeypot.start()
        services.append(http_honeypot)
        click.echo(
            f"   🌐 HTTP Honeypot: listening on "
            f"{cfg.services.http.host}:{cfg.services.http.port}"
        )

    click.echo("\n✅ All services started. Press Ctrl+C to stop.\n")

    try:
        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        # Stop all services
        for service in services:
            await service.stop()


@main.command()
@click.option(
    "--config",
    "-c",
    default="config/honeypot.yml",
    help="Path to configuration file.",
    type=click.Path(exists=True),
)
@click.option(
    "--host",
    "-h",
    default="0.0.0.0",
    help="Host to bind the API server.",
)
@click.option(
    "--port",
    "-p",
    default=8000,
    help="Port for the API server.",
    type=int,
)
@click.option(
    "--reload",
    is_flag=True,
    help="Enable auto-reload for development.",
)
def api(config: str, host: str, port: int, reload: bool) -> None:
    """Start the TenebriNET REST API server."""
    try:
        cfg = load_config(config)

        configure_logger(
            log_level=cfg.logging.level,
            log_format=cfg.logging.format,
            log_output_path=cfg.logging.output,
        )

        click.echo(f"🌐 TenebriNET API v{__version__}")
        click.echo(f"📁 Config: {config}")
        click.echo(f"🔗 Running at: http://{host}:{port}")
        click.echo(f"📚 API Docs: http://{host}:{port}/docs")
        click.echo("")

        uvicorn.run(
            "tenebrinet.api.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info",
        )

    except FileNotFoundError as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        raise SystemExit(1)


@main.command()
@click.option(
    "--config",
    "-c",
    default="config/honeypot.yml",
    help="Path to configuration file.",
    type=click.Path(exists=True),
)
@click.option(
    "--api-port",
    default=8000,
    help="Port for the API server.",
    type=int,
)
def run(config: str, api_port: int) -> None:
    """Run all services including API (combined mode)."""
    try:
        cfg = load_config(config)

        configure_logger(
            log_level=cfg.logging.level,
            log_format=cfg.logging.format,
            log_output_path=cfg.logging.output,
        )

        click.echo(f"🕸️  TenebriNET v{__version__} - Combined Mode")
        click.echo(f"📁 Config: {config}")
        click.echo("")

        asyncio.run(_run_combined(cfg, api_port))

    except FileNotFoundError as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        raise SystemExit(1)
    except KeyboardInterrupt:
        click.echo("\n👋 Shutting down...")


async def _run_combined(cfg, api_port: int) -> None:
    """Run honeypot services and API together."""
    import uvicorn

    from tenebrinet.services.http import HTTPHoneypot
    from tenebrinet.services.ssh import SSHHoneypot

    # Initialize database
    await init_db()
    logger.info("database_initialized")

    services = []

    # Start SSH honeypot if enabled
    if cfg.services.ssh.enabled:
        ssh_honeypot = SSHHoneypot(cfg.services.ssh)
        await ssh_honeypot.start()
        services.append(ssh_honeypot)
        click.echo(
            f"   🔐 SSH: {cfg.services.ssh.host}:{cfg.services.ssh.port}"
        )

    # Start HTTP honeypot if enabled
    if cfg.services.http.enabled:
        http_honeypot = HTTPHoneypot(cfg.services.http)
        await http_honeypot.start()
        services.append(http_honeypot)
        click.echo(
            f"   🌐 HTTP: {cfg.services.http.host}:{cfg.services.http.port}"
        )

    click.echo(f"   🌐 API: http://0.0.0.0:{api_port}/docs")
    click.echo("\n✅ All services started. Press Ctrl+C to stop.\n")

    # Run API server
    config = uvicorn.Config(
        "tenebrinet.api.main:app",
        host="0.0.0.0",
        port=api_port,
        log_level="warning",
    )
    server = uvicorn.Server(config)

    try:
        await server.serve()
    finally:
        for service in services:
            await service.stop()


@main.command()
def status() -> None:
    """Show status of TenebriNET services."""
    click.echo("🔍 Checking TenebriNET status...")
    click.echo("⚠️  Status check not yet implemented.")
    click.echo("   Use the API endpoint: GET /health")


@main.command()
@click.option(
    "--config",
    "-c",
    default="config/honeypot.yml",
    help="Path to configuration file.",
    type=click.Path(exists=True),
)
def validate(config: str) -> None:
    """Validate configuration file."""
    try:
        cfg = load_config(config)
        click.echo(f"✅ Configuration is valid: {config}")
        ssh_status = "enabled" if cfg.services.ssh.enabled else "disabled"
        http_status = "enabled" if cfg.services.http.enabled else "disabled"
        ftp_status = "enabled" if cfg.services.ftp.enabled else "disabled"
        click.echo(f"   📡 SSH: {ssh_status}")
        click.echo(f"   🌐 HTTP: {http_status}")
        click.echo(f"   📂 FTP: {ftp_status}")
    except FileNotFoundError as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        raise SystemExit(1)


@main.command()
def initdb() -> None:
    """Initialize the database schema."""
    click.echo("🗄️  Initializing database...")
    try:
        asyncio.run(init_db())
        click.echo("✅ Database initialized successfully.")
    except Exception as e:
        click.echo(f"❌ Database initialization failed: {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
