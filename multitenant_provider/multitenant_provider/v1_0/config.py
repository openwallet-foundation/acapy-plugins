"""Configuration classes for multitenant_provider."""

import logging
from datetime import timedelta
from typing import Any, Mapping, Optional

from mergedeep import merge
from pydantic import BaseModel

LOGGER = logging.getLogger(__name__)


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class ManagerConfig(BaseModel):
    """Configuration for the multitenant manager."""

    class_name: Optional[str]  # real world, this is a UUID
    always_check_provided_wallet_key: bool = False

    class Config:
        """Inner class for configuration."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        # consider this for local development only...
        return cls(
            class_name="multitenant_provider.v1_0.manager.BasicMultitokenMultitenantManager",
            always_check_provided_wallet_key=True,
        )


class ErrorsConfig(BaseModel):
    """Configuration for error handling."""

    on_unneeded_wallet_key: bool = True

    class Config:
        """Inner class for configuration."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(on_unneeded_wallet_key=True)


class TokenExpiryConfig(BaseModel):
    """Configuration for token expiry."""

    units: Optional[str] = "weeks"  # weeks, days, hours, minutes
    amount: int = 52

    class Config:
        """Inner class for configuration."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(units="weeks", quantity=52)

    def get_token_expiry_delta(self) -> timedelta:
        """Return a timedelta representing the token expiry."""
        result = timedelta(weeks=52)
        if "weeks" == self.units:
            result = timedelta(weeks=self.amount)
        elif "days" == self.units:
            result = timedelta(days=self.amount)
        elif "hours" == self.units:
            result = timedelta(hours=self.amount)
        elif "minutes" == self.units:
            result = timedelta(minutes=self.amount)
        return result


class MultitenantProviderConfig(BaseModel):
    """Configuration for the multitenant provider."""

    manager: Optional[ManagerConfig]
    errors: Optional[ErrorsConfig]
    token_expiry: Optional[TokenExpiryConfig]

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(
            manager=ManagerConfig.default(),
            errors=ErrorsConfig.default(),
            token_expiry=TokenExpiryConfig.default(),
        )


def process_config_dict(config_dict: dict) -> dict:
    """Remove any keys that are not in the config class."""
    _filter = ["manager", "errors", "token_expiry"]
    for key, value in config_dict.items():
        if key in _filter:
            config_dict[key] = value
    return config_dict


def get_config(settings: Mapping[str, Any]) -> MultitenantProviderConfig:
    """Retrieve configuration from settings."""
    try:
        LOGGER.debug("Constructing config from: %s", settings.get("plugin_config"))
        plugin_config_dict = settings["plugin_config"].get("multitenant_provider", {})
        LOGGER.debug("Retrieved: %s", plugin_config_dict)
        plugin_config_dict = process_config_dict(plugin_config_dict)
        LOGGER.debug("Parsed: %s", plugin_config_dict)
        default_config = MultitenantProviderConfig.default().model_dump()
        LOGGER.debug("Default Config: %s", default_config)
        config_dict = merge({}, default_config, plugin_config_dict)
        LOGGER.debug("Merged: %s", config_dict)
        config = MultitenantProviderConfig(**config_dict)
    except KeyError:
        LOGGER.warning("Using default configuration")
        config = MultitenantProviderConfig.default()

    LOGGER.debug("Returning config: %s", config.model_dump_json(indent=2))
    LOGGER.debug(
        "Returning config(aliases): %s", config.model_dump_json(by_alias=True, indent=2)
    )
    return config
