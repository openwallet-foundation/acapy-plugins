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
            f"Invalid {var} specified for Status List plugin; use either status_list.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for Bitstring Plugin."""

    list_size: int
    shard_size: int
    base_url: str
    base_dir: str
    path_template: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("status_list")
        list_size = int(plugin_settings.get("list_size") or getenv("STATUS_LIST_SIZE"))
        shard_size = int(
            plugin_settings.get("shard_size") or getenv("STATUS_LIST_SHARD_SIZE")
        )
        base_url = plugin_settings.get("base_url") or getenv("STATUS_LIST_BASE_URL")
        base_dir = plugin_settings.get("base_dir") or getenv("STATUS_LIST_BASE_DIR")
        path_template = plugin_settings.get("path_template") or getenv(
            "STATUS_LIST_PATH_TEMPLATE"
        )
        if not list_size:
            raise ConfigError("list_size", "STATUS_LIST_SIZE")
        if not shard_size:
            raise ConfigError("shard_size", "STATUS_LIST_SHARD_SIZE")
        if not base_url:
            raise ConfigError("base_url", "STATUS_LIST_BASE_URL")
        if not base_dir:
            raise ConfigError("base_dir", "STATUS_LIST_BASE_DIR")
        if not path_template:
            raise ConfigError("path_template", "STATUS_LIST_PATH_TEMPLATE")

        return cls(list_size, shard_size, base_url, base_dir, path_template)
