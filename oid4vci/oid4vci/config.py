"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv
from aries_cloudagent.core.profile import InjectionContext


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
            raise ValueError(
                "No host specified for OID4VCI server; use either oid4vci.host "
                "plugin config value or environment variable OID4VCI_HOST"
            )
        if not port:
            raise ValueError(
                "No port specified for OID4VCI server; use either oid4vci.port "
                "plugin config value or environment variable OID4VCI_PORT"
            )
        if not endpoint:
            raise ValueError(
                "No endpoint specified for OID4VCI server; use either oid4vci.endpoint "
                "plugin config value or environment variable OID4VCI_ENDPOINT"
            )

        return cls(host, port, endpoint)
