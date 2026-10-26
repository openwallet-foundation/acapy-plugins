"""Keycloak as the wallet-facing authorization server.

Keycloak (with the extension in ``oid4vc/keycloak/extension``) serves the
pre-authorized code token request: it authenticates the wallet with
attestation-based client authentication (ABCA), requires a DPoP proof, and
redeems the plugin-issued code through the redeem endpoint on the plugin's
admin API. The plugin validates the resulting access tokens locally against
the realm JWKS.

Authorization server entry settings::

    {
      "type": "keycloak",
      "public_url": "https://kc.example.com/realms/oid4vci",   # realm issuer
      "private_url": "http://keycloak:8080/realms/oid4vci",    # optional, for JWKS
      "jwks_uri": "...",   # optional, default {private_url}/protocol/openid-connect/certs
      "issuer": "...",     # optional, expected iss (default public_url)
      "audience": "...",   # optional, expected aud (default credential issuer URL)
      "refresh_id_claim": "refresh_id",   # optional
      "require_dpop": true,               # optional
      "redeem_client": {                  # optional: redeem call authentication
        "auth_method": "private_key_jwt", # | client_secret_jwt | client_secret_post
        "client_id": "...",               # default: the realm issuer
        "client_secret": "...",           # for the client_secret_* methods
        "jwks_uri": "...",                # default: the realm JWKS
        "audience": "..."                 # default: the redeem URL as received
      }
    }
"""

import logging
from typing import Any, Mapping

from oid4vc.auth_providers import (
    AuthContext,
    AuthServerConfigError,
    AuthServerProvider,
    InvalidTokenError,
)
from oid4vc.auth_providers.client_auth import (
    CREDENTIAL_ISSUER_CLAIM,
    PRIVATE_KEY_JWT,
    BackChannelClient,
    authenticate_client,
)
from oid4vc.jose_util import (
    JoseAudienceError,
    JoseError,
    JoseIssuerError,
    JWKSCache,
    ReplayCache,
)
from oid4vc.jwt import JWTVerifyResult

LOGGER = logging.getLogger(__name__)

# Keycloak's ``typ`` claim on access tokens, initial or refreshed: ``Bearer``,
# or ``DPoP`` when bound (``bearer`` with a client's deprecated "Use lower-case
# bearer type in token responses" switch, so compared case-insensitively).
# ID and logout tokens are signed with the same realm keys and must not pass
# as access tokens. (Refresh tokens are signed with the realm's internal HMAC
# key, which is not in the JWKS, so they already fail signature verification.)
ACCESS_TOKEN_TYPES = frozenset({"bearer", "dpop"})


class KeycloakProvider(AuthServerProvider):
    """Keycloak realm as the authorization server."""

    type = "keycloak"
    supports_redeem = True

    def __init__(self, jwks_cache: JWKSCache | None = None):
        """Initialize the provider."""
        self._jwks = jwks_cache or JWKSCache()
        self._redeem_jtis = ReplayCache()

    @staticmethod
    def _public_url(ctx: AuthContext) -> str:
        public_url = ctx.setting("public_url")
        if not public_url:
            raise AuthServerConfigError(
                "Keycloak authorization server entry needs public_url (the realm issuer)"
            )
        return public_url.rstrip("/")

    def _issuer(self, ctx: AuthContext) -> str:
        return ctx.setting("issuer", self._public_url(ctx))

    def _jwks_uri(self, ctx: AuthContext) -> str:
        base = (ctx.setting("private_url") or self._public_url(ctx)).rstrip("/")
        return ctx.setting("jwks_uri", f"{base}/protocol/openid-connect/certs")

    def authorization_servers(self, ctx: AuthContext) -> list[str] | None:
        """Advertise the realm as the authorization server."""
        return [self._public_url(ctx)]

    def require_dpop(self, ctx: AuthContext) -> bool:
        """DPoP-bound tokens are required unless disabled."""
        return bool(ctx.setting("require_dpop", True))

    def exchange_key(self, ctx: AuthContext, payload: Mapping[str, Any]) -> str | None:
        """The exchange is identified by a session-note claim, not ``sub``."""
        return payload.get(ctx.setting("refresh_id_claim", "refresh_id"))

    async def validate_access_token(
        self, ctx: AuthContext, token: str
    ) -> JWTVerifyResult:
        """Validate a Keycloak access token against the realm JWKS."""
        try:
            header, payload = await self._jwks.decode(
                self._jwks_uri(ctx),
                token,
                issuer=self._issuer(ctx),
                audience=ctx.setting("audience", ctx.issuer_url),
                require=("exp", "iss", "aud"),
            )
        except JoseIssuerError as err:
            raise InvalidTokenError("Token issuer mismatch") from err
        except JoseAudienceError as err:
            raise InvalidTokenError("Token audience mismatch") from err
        except JoseError as err:
            LOGGER.info("Keycloak access token rejected: %s", err)
            raise InvalidTokenError("Token verification failed") from err

        typ = payload.get("typ")
        if not isinstance(typ, str) or typ.lower() not in ACCESS_TOKEN_TYPES:
            raise InvalidTokenError("Token is not an access token")
        if not self.exchange_key(ctx, payload):
            raise InvalidTokenError("Token does not reference a credential exchange")
        return JWTVerifyResult(headers=header, payload=payload, verified=True)

    def redeem_client(self, ctx: AuthContext) -> BackChannelClient:
        """Expected client authentication for redeem calls from this realm."""
        conf = ctx.setting("redeem_client", {}) or {}
        return BackChannelClient(
            client_id=conf.get("client_id") or self._issuer(ctx),
            auth_method=conf.get("auth_method") or PRIVATE_KEY_JWT,
            client_secret=conf.get("client_secret"),
            jwks_uri=conf.get("jwks_uri") or self._jwks_uri(ctx),
            audience=conf.get("audience"),
        )

    async def authenticate_back_channel(
        self,
        ctx: AuthContext,
        params: Mapping[str, str],
        endpoint_url: str,
    ) -> None:
        """Authenticate a redeem call from the realm (RFC 7523 client auth).

        The caller must also state, in its signed assertion (or, with
        ``client_secret_post``, as a form parameter), the credential issuer
        identifier of the tenant it acts for.
        """
        await authenticate_client(
            self.redeem_client(ctx),
            params,
            endpoint_url,
            jwks_cache=self._jwks,
            replay_cache=self._redeem_jtis,
            required_claims={CREDENTIAL_ISSUER_CLAIM: ctx.issuer_url},
        )
