"""Utilities for shared functions."""

import hashlib
import json

from acapy_agent.core.profile import Profile
from acapy_agent.utils.multiformats import multibase

from .exceptions import ConfigurationError


def get_plugin_settings(profile: Profile):
    """Get the plugin settings."""
    return profile.settings.get("plugin_config", {}).get("did-webvh", {})


def is_controller(profile: Profile):
    """Check if the current agent is the controller."""
    return get_plugin_settings(profile).get("role") == "controller"


def get_server_url(profile: Profile):
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


def create_digest_multibase(json_obj, multibase_encoding="base58btc"):
    """Create a digest multibase of a JSON object.

    Args:
        json_obj (dict): The JSON object to encode.
        multibase_encoding (str): The multibase encoding format (e.g., 'base58btc').

    Returns:
        str: The multibase-encoded hash of the JSON object.
    """
    # Serialize JSON object to a compact string
    json_str = json.dumps(json_obj, separators=(",", ":"))

    # Compute SHA-256 hash of the JSON string
    json_hash = hashlib.sha256(json_str.encode("utf-8")).digest()

    # Encode the hash using multibase
    multibase_hash = multibase.encode(json_hash, multibase_encoding)

    return multibase_hash.decode("utf-8")
