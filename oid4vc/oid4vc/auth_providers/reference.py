"""Reference authorization server (``oid4vc/auth_server``)."""

import logging

from aiohttp import web

from ..app_resources import AppResources
from ..jwt import JWTVerifyResult
from ..utils import get_auth_header, get_auth_server_url
from .base import AuthContext, AuthServerProvider, InvalidTokenError

LOGGER = logging.getLogger(__name__)


class ReferenceProvider(AuthServerProvider):
    """The separate reference authorization server.

    It mints pre-authorized codes (``POST {private_url}/grants/pre-authorized-code``)
    and serves ``/token``; the plugin validates tokens by introspection.

    Settings (authorization server entry): ``public_url``, ``private_url``,
    ``auth_type`` + ``client_credentials`` (how the plugin authenticates to the
    AS), optional ``introspection_endpoint`` (default ``{private_url}/introspect``).
    """

    type = "reference"

    async def create_pre_authorized_code(
        self,
        ctx: AuthContext,
        *,
        subject_id,
        credential_configuration_id,
        user_pin,
    ) -> str:
        """Ask the reference AS to mint a pre-authorized code."""
        private_url = get_auth_server_url(ctx.auth_server)
        grants_endpoint = f"{private_url}/grants/pre-authorized-code"
        auth_header = await get_auth_header(
            ctx.profile, ctx.auth_server, ctx.issuer_url, grants_endpoint
        )
        resp = await AppResources.get_http_client().post(
            grants_endpoint,
            json={
                "subject_id": subject_id,
                "user_pin_required": user_pin is not None,
                "user_pin": user_pin,
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "credential_configuration_id": credential_configuration_id,
                    }
                ],
            },
            headers={"Authorization": f"{auth_header}"},
        )
        if resp.status != 200:
            body = await resp.text()
            raise web.HTTPBadGateway(reason=f"Auth server returned {resp.status}: {body}")
        data = await resp.json()
        return data["pre_authorized_code"]

    async def validate_access_token(
        self, ctx: AuthContext, token: str
    ) -> JWTVerifyResult:
        """Validate a token by RFC 7662 introspection."""
        introspect_endpoint = ctx.setting(
            "introspection_endpoint",
            f"{get_auth_server_url(ctx.auth_server)}/introspect",
        )
        auth_header = await get_auth_header(
            ctx.profile, ctx.auth_server, ctx.issuer_url, introspect_endpoint
        )
        resp = await AppResources.get_http_client().post(
            introspect_endpoint,
            data={"token": token},
            headers={"Authorization": auth_header},
        )
        if resp.status != 200:
            LOGGER.warning("Token introspection failed: HTTP %s", resp.status)
            raise InvalidTokenError("Token introspection failed")
        introspect = await resp.json()
        if not introspect.get("active"):
            raise InvalidTokenError("Token is not active")
        return JWTVerifyResult(headers={}, payload=introspect, verified=True)
