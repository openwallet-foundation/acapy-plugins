"""Authorization server provider interface.

The OID4VC plugin is always the Credential Issuer and the resource server for
``/credential``. Which component acts as the wallet-facing OAuth authorization
server is pluggable: each mode is an ``AuthServerProvider`` selected by the
``type`` of the configured authorization server entry (see ``registry.py``).
"""

import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from acapy_agent.core.profile import Profile

from ..config import Config
from ..jwt import JWTVerifyResult
from ..utils import get_tenant_subpath

CODE_BYTES = 32


class InvalidTokenError(Exception):
    """An access token was rejected by the provider."""

    def __init__(self, description: str = "Token verification failed"):
        """Initialize the error."""
        super().__init__(description)
        self.description = description


class BackChannelAuthError(Exception):
    """A back-channel request from the authorization server was not authenticated."""


class AuthServerConfigError(ValueError):
    """The authorization server configuration is invalid or unsupported."""


@dataclass
class AuthContext:
    """Per-request context handed to providers."""

    profile: Profile
    config: Config
    # The authorization server entry ({"type": ..., "public_url": ..., ...});
    # empty for the built-in server when nothing is configured.
    auth_server: Mapping[str, Any] = field(default_factory=dict)

    @property
    def issuer_url(self) -> str:
        """Credential Issuer Identifier for the current tenant."""
        subpath = get_tenant_subpath(self.profile, tenant_prefix="/tenant")
        return f"{self.config.endpoint}{subpath}"

    def setting(self, key: str, default: Any = None) -> Any:
        """Read a provider setting from the authorization server entry."""
        value = self.auth_server.get(key)
        return default if value is None else value


class AccessTokenResult(JWTVerifyResult):
    """A validated access token plus the exchange it authorizes."""

    def __init__(
        self,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
        verified: bool,
        exchange_key: str | None = None,
    ):
        """Initialize the result."""
        super().__init__(headers, payload, verified)
        self.exchange_key = exchange_key


class AuthServerProvider:
    """Base class for authorization server integrations."""

    #: value of the ``type`` key that selects this provider
    type: str = ""
    #: whether the plugin's own ``/token`` endpoint serves wallets in this mode
    serves_token_endpoint: bool = False
    #: whether the authorization server redeems plugin-issued pre-authorized
    #: codes through ``POST /oid4vci/pre-auth/redeem``
    supports_redeem: bool = False

    async def create_pre_authorized_code(
        self,
        ctx: AuthContext,
        *,
        subject_id: str,
        credential_configuration_id: str | None,
        user_pin: str | None,
    ) -> str:
        """Mint the pre-authorized code placed in a credential offer.

        By default the plugin mints an opaque random code itself.
        """
        return secrets.token_urlsafe(CODE_BYTES)

    async def validate_access_token(
        self, ctx: AuthContext, token: str
    ) -> JWTVerifyResult:
        """Validate an access token presented at the credential endpoint.

        Raises ``InvalidTokenError`` if the token is not acceptable.
        """
        raise NotImplementedError()

    def exchange_key(self, ctx: AuthContext, payload: Mapping[str, Any]) -> str | None:
        """Return the exchange ``refresh_id`` a validated token authorizes."""
        return payload.get("sub")

    def require_dpop(self, ctx: AuthContext) -> bool:
        """Whether access tokens must be DPoP-bound (``cnf.jkt``)."""
        return False

    def authorization_servers(self, ctx: AuthContext) -> list[str] | None:
        """Values for ``authorization_servers`` in the issuer metadata."""
        public_url = ctx.auth_server.get("public_url")
        return [public_url] if public_url else None

    async def authenticate_back_channel(
        self,
        ctx: AuthContext,
        params: Mapping[str, str],
        endpoint_url: str,
    ) -> None:
        """Authenticate a back-channel (redeem) request from the AS.

        ``params`` are the request's form parameters (which carry the client
        credentials); ``endpoint_url`` is the URL the request was sent to.
        Raises ``BackChannelAuthError``.
        """
        raise BackChannelAuthError("back-channel requests are not supported")
