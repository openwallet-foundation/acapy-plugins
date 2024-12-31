"""Load configuration params."""

from dataclasses import dataclass
from os import getenv

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for Hedera DID plugin; use either "
            f"hedera_did.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for Hedera DID plugin."""

    network: str
    operator_id: str
    operator_key_der: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("hedera_did")

        network = ( plugin_settings.get("network") 
                   or getenv("HEDERA_DID_NETWORK") )
        operator_id = ( plugin_settings.get("operator_id") 
                       or getenv("HEDERA_DID_OPERATOR_ID") )
        operator_key_der = ( plugin_settings.get("operator_key_der") 
                            or getenv("HEDERA_DID_OPERATOR_KEY_DER") )

        if not network:
            raise ConfigError("network", "HEDERA_DID_NETWORK")
        if not operator_id:
            raise ConfigError("operator_id", "HEDERA_DID_OPERATOR_ID")
        if not operator_key_der:
            raise ConfigError("operator_key_der", "HEDERA_DID_OPERATOR_KEY_DER")

        return cls(network, operator_id, operator_key_der)

