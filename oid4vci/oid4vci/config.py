"""Retrieve configuration values."""

from typing import Any, Optional, overload
from aries_cloudagent.core.profile import InjectionContext

MISSING = object()


class Config:
    """Configuration for OID4VCI.

    Expected configuration options:
    host: The host to listen on.
        -o oid4vci.host=...
        OID4VCI_HOST=...
    port: The port to listen on.
        -o oid4vci.port=...
        OID4VCI_PORT=...
    endpoint: The endpoint to listen on.
        -o oid4vci.endpoint=...
        OID4VCI_ENDPOINT=...
    """

    def __init__(self, context: InjectionContext):
        """Initialize the configuration."""
        self.context = context
        self.plugin_settings = context.settings.for_plugin("oid4vci")

    @overload
    def get_plugin_setting_or_env(self, setting: str, var: str) -> Optional[Any]:
        ...

    @overload
    def get_plugin_setting_or_env(self, setting: str, var: str, default: Any) -> Any:
        ...

    def get_plugin_setting_or_env(self, setting: str, var: str, default: Any = MISSING):
        """Get a plugin setting or environment variable."""
        value = self.plugin_settings.get(setting) or self.context.settings.get(
            var, default
        )
        if value is MISSING:
            return None
        return value

    @property
    def host(self) -> str:
        """Get the host."""
        return self.get_plugin_setting_or_env("host", "OID4VCI_HOST", "0.0.0.0")

    @property
    def port(self) -> int:
        """Get the port."""
        return int(self.get_plugin_setting_or_env("port", "OID4VCI_PORT", "8081"))

    @property
    def endpoint(self) -> str:
        """Get the endpoint."""
        return self.get_plugin_setting_or_env("endpoint", "OID4VCI_ENDPOINT", "oid4vci")
