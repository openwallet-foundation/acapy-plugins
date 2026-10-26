"""Registry and resolution of authorization server providers.

Selection, highest priority first:

1. the tenant's ``IssuerConfiguration.authorization_servers[0]``;
2. the plugin-level ``oid4vci.auth_server`` setting / ``OID4VCI_AUTH_SERVER``;
3. the built-in authorization server.

The entry's ``type`` key names the provider. Entries without ``type`` predate
pluggable providers and refer to the reference authorization server
(``oid4vc/auth_server``).
"""

from typing import Any, Mapping, Tuple

from acapy_agent.core.profile import Profile, ProfileSession

from ..config import Config
from ..utils import get_first_auth_server
from .base import AuthContext, AuthServerConfigError, AuthServerProvider

BUILTIN = "builtin"
REFERENCE = "reference"


class AuthServerRegistry:
    """Maps an authorization server ``type`` to its provider."""

    def __init__(self):
        """Initialize an empty registry."""
        self._providers: dict[str, AuthServerProvider] = {}

    def register(self, provider: AuthServerProvider) -> None:
        """Register a provider under its ``type``."""
        if not provider.type:
            raise ValueError("provider has no type")
        self._providers[provider.type] = provider

    def get(self, type_: str) -> AuthServerProvider:
        """Return the provider for ``type_``."""
        try:
            return self._providers[type_]
        except KeyError:
            raise AuthServerConfigError(
                f"No authorization server provider for type '{type_}'; "
                f"available: {', '.join(sorted(self._providers))}. "
                "Is the plugin providing it loaded?"
            ) from None

    @property
    def types(self) -> list[str]:
        """Registered provider types."""
        return sorted(self._providers)


def default_registry() -> AuthServerRegistry:
    """Registry with the providers built into the core plugin."""
    from .builtin import BuiltinProvider  # noqa: PLC0415
    from .reference import ReferenceProvider  # noqa: PLC0415

    registry = AuthServerRegistry()
    registry.register(BuiltinProvider())
    registry.register(ReferenceProvider())
    return registry


def provider_type(entry: Mapping[str, Any] | None) -> str:
    """Return the provider type named by an authorization server entry."""
    if not entry:
        return BUILTIN
    return entry.get("type") or REFERENCE


def auth_provider_for_entry(
    profile: Profile, entry: Mapping[str, Any] | None
) -> Tuple[AuthServerProvider, AuthContext]:
    """Return the provider and context for a tenant's authorization server entry.

    Without an entry, falls back to the plugin-level setting, then the built-in
    authorization server.
    """
    config = Config.from_settings(profile.settings)
    if entry is None:
        entry = config.auth_server
    registry = profile.inject_or(AuthServerRegistry) or default_registry()
    provider = registry.get(provider_type(entry))
    return provider, AuthContext(profile, config, dict(entry or {}))


async def resolve_auth_provider(
    session: ProfileSession, profile: Profile
) -> Tuple[AuthServerProvider, AuthContext]:
    """Resolve the provider and context for the current tenant."""
    return auth_provider_for_entry(profile, await get_first_auth_server(session, profile))
