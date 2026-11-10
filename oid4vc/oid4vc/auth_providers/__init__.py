"""Pluggable authorization server providers."""

from .base import (
    AccessTokenResult,
    AuthContext,
    AuthServerConfigError,
    AuthServerProvider,
    BackChannelAuthError,
    InvalidTokenError,
)
from .registry import (
    BUILTIN,
    REFERENCE,
    AuthServerRegistry,
    auth_provider_for_entry,
    default_registry,
    provider_type,
    resolve_auth_provider,
)

__all__ = [
    "AccessTokenResult",
    "AuthContext",
    "AuthServerConfigError",
    "AuthServerProvider",
    "AuthServerRegistry",
    "BackChannelAuthError",
    "BUILTIN",
    "InvalidTokenError",
    "REFERENCE",
    "auth_provider_for_entry",
    "default_registry",
    "provider_type",
    "resolve_auth_provider",
]
