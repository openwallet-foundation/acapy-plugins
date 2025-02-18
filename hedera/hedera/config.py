"""Hedera configuration."""

from dataclasses import dataclass
from os import getenv
from typing import Optional

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initializer."""
        super().__init__(
            f"Invalid {var} specified for Hedera DID plugin; use either "
            f"hedera.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for Hedera DID plugin."""

    network: str
    operator_id: str
    operator_key: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from application context settings class."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("hedera")

        network: Optional[str] = plugin_settings.get("network") or getenv(
            "HEDERA_NETWORK"
        )
        operator_id: Optional[str] = plugin_settings.get("operator_id") or getenv(
            "HEDERA_OPERATOR_ID"
        )
        operator_key: Optional[str] = plugin_settings.get("operator_key") or getenv(
            "HEDERA_OPERATOR_KEY"
        )

        if not network:
            raise ConfigError("network", "HEDERA_NETWORK")
        if not operator_id:
            raise ConfigError("operator_id", "HEDERA_OPERATOR_ID")
        if not operator_key:
            raise ConfigError("operator_key", "HEDERA_OPERATOR_KEY")

        return cls(network, operator_id, operator_key)
