"""Configuration classes for multitenant_provider."""

import logging
from typing import Any, Mapping

from mergedeep import merge
from pydantic import BaseModel

LOGGER = logging.getLogger(__name__)


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class BasicMessageStorageConfig(BaseModel):
    """Configuration for the basicmessage_storage."""

    wallet_enabled: bool = False

    class Config:
        """Inner class for configuration."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        # consider this for local development only...
        return cls()


def process_config_dict(config_dict: dict) -> dict:
    """Remove any keys that are not in the config class."""
    _filter = BasicMessageStorageConfig.default().model_dump().keys()
    for key, value in config_dict.items():
        if key in _filter:
            config_dict[key] = value
    return config_dict


def get_config(settings: Mapping[str, Any]) -> BasicMessageStorageConfig:
    """Retrieve configuration from settings."""
    try:
        LOGGER.debug(
            "Constructing config from: %s",
            settings.get("plugin_config", {}).get("basicmessage_storage"),
        )
        global_plugin_config_dict = settings.get("plugin_config", {}).get(
            "basicmessage_storage", {}
        )
        tenant_plugin_config_dict = settings.get("basicmessage_storage", {})
        LOGGER.debug("Retrieved (global): %s", global_plugin_config_dict)
        LOGGER.debug("Retrieved (tenant)): %s", tenant_plugin_config_dict)
        global_plugin_config_dict = process_config_dict(global_plugin_config_dict)
        tenant_plugin_config_dict = process_config_dict(tenant_plugin_config_dict)
        LOGGER.debug("Parsed (global): %s", global_plugin_config_dict)
        LOGGER.debug("Parsed (tenant): %s", tenant_plugin_config_dict)
        default_config = BasicMessageStorageConfig.default().model_dump()
        LOGGER.debug("Default Config: %s", default_config)
        config_dict = merge(
            {}, default_config, global_plugin_config_dict, tenant_plugin_config_dict
        )
        LOGGER.debug("Merged: %s", config_dict)
        config = BasicMessageStorageConfig(**config_dict)
    except KeyError:
        LOGGER.warning("Using default configuration")
        config = BasicMessageStorageConfig.default()

    LOGGER.debug("Returning config: %s", config.model_dump_json(indent=2))
    LOGGER.debug(
        "Returning config(aliases): %s", config.model_dump_json(by_alias=True, indent=2)
    )
    return config
