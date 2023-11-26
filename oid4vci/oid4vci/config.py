"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv
from aries_cloudagent.core.profile import InjectionContext


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

    @classmethod
    def from_context(cls, context: InjectionContext) -> "Config":
        """Retrieve configuration from context."""
        plugin_settings = context.settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        endpoint = plugin_settings.get("endpoint") or getenv("OID4VCI_ENDPOINT")

        if not host:
            raise ConfigError("host", "OID4VCI_HOST")
        if not port:
            raise ConfigError("port", "OID4VCI_PORT")
        if not endpoint:
            raise ConfigError("endpoint", "OID4VCI_ENDPOINT")

        return cls(host, port, endpoint)
