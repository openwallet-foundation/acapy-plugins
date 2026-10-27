"""Retrieve configuration values."""

import json
import re
from dataclasses import dataclass
from os import getenv
from typing import Any

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
    # OID4VP public endpoint (may differ from OID4VCI endpoint).
    # Reads OID4VP_ENDPOINT env var; falls back to OID4VCI endpoint if not set.
    oid4vp_endpoint: str | None = None
    status_handler: str | None = None
    # When True, the /nonce endpoint is published and nonces are managed locally.
    # Nonce validation uses DB-based redemption, ignoring c_nonce from access tokens.
    enable_nonce_endpoint: bool = True
    # Plugin-level authorization server configuration, used when the tenant's
    # IssuerConfiguration has no authorization_servers entry. A dict with a
    # "type" key: "builtin" (default when unset), "reference" or "keycloak".
    auth_server: dict[str, Any] | None = None
    # Failed tx_code attempts allowed per pre-authorized code before the code
    # is locked.
    max_tx_code_attempts: int = 5

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        # Prefer environment variable for endpoint to allow tests and deployments
        # to override any static plugin configuration. This ensures the
        # credential_issuer matches the intended OID4VCI base URL.
        endpoint = getenv("OID4VCI_ENDPOINT") or plugin_settings.get("endpoint")
        # OID4VP endpoint may differ (e.g., behind a separate TLS proxy).
        oid4vp_endpoint = getenv("OID4VP_ENDPOINT") or None
        status_handler = plugin_settings.get("status_handler") or getenv(
            "OID4VCI_STATUS_HANDLER"
        )
        # Enable/disable the /nonce endpoint. Defaults to True.
        enable_nonce_raw = plugin_settings.get("enable_nonce_endpoint")
        if enable_nonce_raw is None:
            enable_nonce_raw = getenv("OID4VCI_ENABLE_NONCE_ENDPOINT", "true")
        if str(enable_nonce_raw).lower() not in ("true", "false"):
            raise ConfigError("enable_nonce_endpoint", "OID4VCI_ENABLE_NONCE_ENDPOINT")
        enable_nonce_endpoint = str(enable_nonce_raw).lower() == "true"

        auth_server_raw = plugin_settings.get("auth_server") or getenv(
            "OID4VCI_AUTH_SERVER"
        )
        auth_server = None
        if auth_server_raw:
            try:
                auth_server = (
                    json.loads(auth_server_raw)
                    if isinstance(auth_server_raw, str)
                    else dict(auth_server_raw)
                )
            except (ValueError, TypeError) as err:
                raise ConfigError("auth_server", "OID4VCI_AUTH_SERVER") from err
            if not isinstance(auth_server, dict):
                raise ConfigError("auth_server", "OID4VCI_AUTH_SERVER")

        max_attempts_raw = plugin_settings.get("max_tx_code_attempts") or getenv(
            "OID4VCI_MAX_TX_CODE_ATTEMPTS", "5"
        )
        try:
            max_tx_code_attempts = int(max_attempts_raw)
        except (TypeError, ValueError) as err:
            raise ConfigError(
                "max_tx_code_attempts", "OID4VCI_MAX_TX_CODE_ATTEMPTS"
            ) from err
        if max_tx_code_attempts < 1:
            raise ConfigError("max_tx_code_attempts", "OID4VCI_MAX_TX_CODE_ATTEMPTS")

        if not host:
            raise ConfigError("host", "OID4VCI_HOST")
        if not port:
            raise ConfigError("port", "OID4VCI_PORT")
        if not endpoint:
            raise ConfigError("endpoint", "OID4VCI_ENDPOINT")

        # Expand environment variables in endpoint if needed
        # Handle ${VAR:-default} format
        def expand_vars(text):
            def replacer(match):
                var_expr = match.group(1)
                if ":-" in var_expr:
                    var_name, default_value = var_expr.split(":-", 1)
                    return getenv(var_name.strip(), default_value.strip())
                else:
                    return getenv(var_expr.strip(), match.group(0))

            return re.sub(r"\$\{([^}]+)\}", replacer, text)

        # The endpoint is the Credential Issuer Identifier and the base of
        # every public URL ({endpoint}/tenant/{id}/credential): no trailing slash.
        endpoint = expand_vars(endpoint).rstrip("/")

        return cls(
            host,
            port,
            endpoint,
            oid4vp_endpoint=oid4vp_endpoint,
            status_handler=status_handler,
            enable_nonce_endpoint=enable_nonce_endpoint,
            auth_server=auth_server,
            max_tx_code_attempts=max_tx_code_attempts,
        )
