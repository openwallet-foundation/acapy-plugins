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
            (
                f"Invalid {var} specified for Status List plugin; "
                f"use either status_list.{var} plugin config value "
                f"or environment variable {env}"
            )
        )


@dataclass
class Config:
    """Configuration for Bitstring Plugin."""

    list_size: int
    shard_size: int
    public_uri: str
    file_path: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("status_list")
        list_size = int(
            plugin_settings.get("list_size") or getenv("STATUS_LIST_SIZE") or "0"
        )
        shard_size = int(
            plugin_settings.get("shard_size") or getenv("STATUS_LIST_SHARD_SIZE") or "0"
        )
        public_uri = plugin_settings.get("public_uri") or getenv("STATUS_LIST_PUBLIC_URI")
        file_path = plugin_settings.get("file_path") or getenv("STATUS_LIST_FILE_PATH")
        if not list_size:
            raise ConfigError("list_size", "STATUS_LIST_SIZE")
        if not shard_size:
            raise ConfigError("shard_size", "STATUS_LIST_SHARD_SIZE")
        if not public_uri:
            raise ConfigError("public_uri", "STATUS_LIST_PUBLIC_URI")
        if not file_path:
            raise ConfigError("file_path", "STATUS_LIST_FILE_PATH")

        return cls(list_size, shard_size, public_uri, file_path)
