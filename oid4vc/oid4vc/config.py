"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for OID4VCI server; use either "
            f"oid4vci.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for OID4VCI Plugin."""

    host: str
    port: int
    endpoint: str
    status_handler: str | None = None
    auth_server_url: str | None = None
    auth_server_client: str | None = None

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        endpoint = plugin_settings.get("endpoint") or getenv("OID4VCI_ENDPOINT")
        status_handler = plugin_settings.get("status_handler") or getenv(
            "OID4VCI_STATUS_HANDLER"
        )
        auth_server_url = plugin_settings.get("auth_server_url") or getenv(
            "OID4VCI_AUTH_SERVER_URL"
        )
        auth_server_client = plugin_settings.get("auth_server_client") or getenv(
            "OID4VCI_AUTH_SERVER_CLIENT"
        )
        if not host:
            raise ConfigError("host", "OID4VCI_HOST")
        if not port:
            raise ConfigError("port", "OID4VCI_PORT")
        if not endpoint:
            raise ConfigError("endpoint", "OID4VCI_ENDPOINT")

        return cls(
            host, port, endpoint, status_handler, auth_server_url, auth_server_client
        )
