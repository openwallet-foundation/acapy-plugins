"""Utilities for shared functions."""

from acapy_agent.core.profile import Profile

from .exceptions import ConfigurationError


def get_plugin_settings(profile: Profile):
    """Get the plugin settings."""
    return profile.settings.get("plugin_config", {}).get("did-webvh", {})


def is_controller(profile: Profile):
    """Check if the current agent is the controller."""
    return get_plugin_settings(profile).get("role") == "controller"


def get_server_info(profile: Profile):
    """Get the server info."""
    server_url = get_plugin_settings(profile).get("server_url")

    if not server_url:
        raise ConfigurationError("Invalid configuration. Check server url is set.")

    return server_url


def use_strict_ssl(profile: Profile):
    """Check if the agent should use strict SSL."""
    return get_plugin_settings(profile).get("strict_ssl", True)


def get_url_decoded_domain(domain: str):
    """Replace %3A with : if domain is URL encoded."""
    if "%3A" in domain:
        return domain.replace("%3A", ":")
    return domain
