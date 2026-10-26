"""Built-in authorization server: the plugin's own ``/token`` endpoint."""

import time

from ..did_utils import retrieve_or_create_did_jwk
from ..jwt import JWTVerifyResult, jwt_verify
from .base import AuthContext, AuthServerProvider, InvalidTokenError


class BuiltinProvider(AuthServerProvider):
    """The plugin issues and verifies its own access tokens.

    Tokens are JWTs signed with the tenant's default ``did:jwk``. When the
    wallet sends a DPoP proof to ``/token`` the token is DPoP-bound
    (``cnf.jkt``).
    """

    type = "builtin"
    serves_token_endpoint = True

    def authorization_servers(self, ctx: AuthContext) -> list[str] | None:
        """The issuer is its own authorization server; nothing to advertise."""
        return None

    async def validate_access_token(
        self, ctx: AuthContext, token: str
    ) -> JWTVerifyResult:
        """Verify a token issued by the built-in ``/token`` endpoint."""
        try:
            result = await jwt_verify(ctx.profile, token)
        except Exception as err:
            raise InvalidTokenError("Token verification failed") from err
        if not result.verified:
            raise InvalidTokenError("Token verification failed")

        # jwt_verify accepts any resolvable key; only tokens signed with this
        # issuer's own token key are ours.
        async with ctx.profile.session() as session:
            jwk_info = await retrieve_or_create_did_jwk(session)
        if result.headers.get("kid") != f"{jwk_info.did}#0":
            raise InvalidTokenError("Token was not issued by this issuer")

        exp = result.payload.get("exp")
        if not isinstance(exp, (int, float)) or exp < time.time():
            raise InvalidTokenError("Token expired")
        return result
