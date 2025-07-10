import pytest
from copy import deepcopy

from acapy_agent.config.plugin_settings import PLUGIN_CONFIG_KEY
from acapy_agent.config.settings import Settings

from ..config import Config, ConfigError


@pytest.mark.asyncio
async def test_config(plugin_settings: dict):
    # Test ConfigError
    error = ConfigError("list_size", plugin_settings)
    assert error

    # Test success
    config = Config.from_settings(Settings(plugin_settings))
    assert config

    # Test missing settings
    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["list_size"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["shard_size"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["public_uri"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["file_path"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error
