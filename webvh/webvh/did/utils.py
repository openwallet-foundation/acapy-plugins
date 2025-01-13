"""Utilities for shared functions."""

from acapy_agent.core.profile import Profile

from .exceptions import ConfigurationError


def get_plugin_settings(profile: Profile):
    """Get the plugin settings."""
    return profile.settings.get("plugin_config", {}).get("did-webvh", {})


def is_author(profile: Profile):
    """Check if the current agent is the author."""
    return get_plugin_settings(profile).get("role") == "author"


def get_server_info(profile: Profile):
    """Get the server info."""
    server_url = get_plugin_settings(profile).get("server_url")

    if not server_url:
        raise ConfigurationError("Invalid configuration. Check server url is set.")

    return server_url
