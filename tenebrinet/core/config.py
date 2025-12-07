# tenebrinet/core/config.py
"""
Configuration management for TenebriNET.

Handles loading YAML configuration files with environment variable substitution
and validation using Pydantic models.
"""
import os
import re
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, Field


class SSHServiceConfig(BaseModel):
    """SSH honeypot service configuration."""

    enabled: bool = True
    port: int = 2222
    host: str = "0.0.0.0"
    banner: str = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    max_connections: int = 100
    timeout: int = 30


class HTTPServiceConfig(BaseModel):
    """HTTP honeypot service configuration."""

    enabled: bool = True
    port: int = 8080
    host: str = "0.0.0.0"
    fake_cms: str = "WordPress 5.8"
    serve_files: bool = True


class FTPServiceConfig(BaseModel):
    """FTP honeypot service configuration."""

    enabled: bool = True
    port: int = 2121
    host: str = "0.0.0.0"
    anonymous_allowed: bool = True
    timeout: int = 30


class ServicesConfig(BaseModel):
    """Container for all service configurations."""

    ssh: SSHServiceConfig
    http: HTTPServiceConfig
    ftp: FTPServiceConfig


class DatabaseConfig(BaseModel):
    """Database connection configuration."""

    url: str
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


class RedisConfig(BaseModel):
    """Redis connection configuration."""

    url: str


class MLConfig(BaseModel):
    """Machine learning engine configuration."""

    model_path: str = "data/models/threat_classifier.joblib"
    retrain_interval: str = "24h"
    confidence_threshold: float = 0.7
    features: List[str] = Field(default_factory=list)


class AbuseIPDBConfig(BaseModel):
    """AbuseIPDB threat intelligence configuration."""

    enabled: bool = True
    api_key: str
    check_on_connect: bool = True


class VirusTotalConfig(BaseModel):
    """VirusTotal threat intelligence configuration."""

    enabled: bool = False
    api_key: Optional[str] = None


class ThreatIntelConfig(BaseModel):
    """Container for threat intelligence configurations."""

    abuseipdb: AbuseIPDBConfig
    virustotal: VirusTotalConfig


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "console"] = "json"
    output: str = "data/logs/tenebrinet.log"
    rotation: str = "100 MB"


class TenebriNetConfig(BaseModel):
    """Root configuration model for TenebriNET."""

    services: ServicesConfig
    database: DatabaseConfig
    redis: RedisConfig
    ml: MLConfig
    threat_intel: ThreatIntelConfig
    logging: LoggingConfig


# Regex pattern for ${VAR_NAME} or ${VAR_NAME:default}
ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)(?::([^}]*))?\}")


def substitute_env_vars(content: str) -> str:
    """
    Substitute environment variables in the format ${VAR} or ${VAR:default}.

    Args:
        content: String content with environment variable placeholders.

    Returns:
        String with environment variables substituted.
    """

    def replace(match: re.Match) -> str:
        var_name = match.group(1)
        default_value = match.group(2)
        return os.environ.get(
            var_name, default_value if default_value is not None else ""
        )

    return ENV_VAR_PATTERN.sub(replace, content)


def load_config(config_path: str = "config/honeypot.yml") -> TenebriNetConfig:
    """
    Load configuration from a YAML file.

    Loads the YAML file, substitutes environment variables,
    and validates it against the Pydantic schema.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Validated TenebriNetConfig object.

    Raises:
        FileNotFoundError: If the configuration file doesn't exist.
        ValueError: If the YAML is invalid or fails validation.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Configuration file not found at: {config_path}"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        raw_content = f.read()

    # Substitute environment variables
    processed_content = substitute_env_vars(raw_content)

    # Parse YAML
    try:
        config_dict = yaml.safe_load(processed_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML configuration: {e}") from e

    # Validate with Pydantic
    try:
        config = TenebriNetConfig(**config_dict)
        return config
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}") from e
