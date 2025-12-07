# tenebrinet/cli.py
"""
Command-line interface for TenebriNET.

Provides CLI commands for starting the honeypot services, managing
configuration, and monitoring system health.
"""
import click
import structlog

from tenebrinet import __version__
from tenebrinet.core.config import load_config
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
    """Start the TenebriNET honeypot services."""
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

        # TODO: Implement service startup
        click.echo("⚠️  Service startup not yet implemented.")

    except FileNotFoundError as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)
    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        raise SystemExit(1)


@main.command()
def status() -> None:
    """Show status of TenebriNET services."""
    click.echo("🔍 Checking TenebriNET status...")
    click.echo("⚠️  Status check not yet implemented.")


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


if __name__ == "__main__":
    main()
