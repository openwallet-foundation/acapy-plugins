"""Token endpoint and authentication utilities."""

import logging
import time
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.util import datetime_now
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.error import WalletNotFoundError, WalletError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
)
from aries_askar import Key
from marshmallow import fields

from oid4vc.jwt import jwt_sign, jwt_verify, key_material_for_kid, JWTVerifyResult

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.nonce import Nonce
from ..pop_result import PopResult
from ..utils import get_auth_header, get_tenant_subpath

LOGGER = logging.getLogger(__name__)
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
NONCE_BYTES = 16
EXPIRES_IN = 86400


class GetTokenSchema(OpenAPISchema):
    """Schema for ..."""

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)


@docs(tags=["oid4vc"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""
    context = request["context"]
    config = Config.from_settings(context.settings)
    if config.auth_server_url:
        subpath = get_tenant_subpath(context.profile)
        token_url = f"{config.auth_server_url}{subpath}/token"
        raise web.HTTPTemporaryRedirect(location=token_url)

    context: AdminRequestContext = request["context"]
    form = await request.post()
    LOGGER.debug(f"Token request: {form}")
    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        raise web.HTTPBadRequest(reason="grant_type not supported")

    pre_authorized_code = form.get("pre-authorized_code")
    if not pre_authorized_code or not isinstance(pre_authorized_code, str):
        raise web.HTTPBadRequest(reason="pre-authorized_code is missing or invalid")

    user_pin = request.query.get("user_pin")
    try:
        async with context.profile.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                session, pre_authorized_code
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if record.pin is not None:
        if user_pin is None:
            raise web.HTTPBadRequest(reason="user_pin is required")
        if user_pin != record.pin:
            raise web.HTTPBadRequest(reason="pin is invalid")

    payload = {
        "sub": record.refresh_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }
    async with context.profile.session() as session:
        try:
            token = await jwt_sign(
                context.profile,
                headers={},
                payload=payload,
                verification_method=record.verification_method,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            raise web.HTTPBadRequest(reason="Bad did or verification method") from err

        record.token = token
        record.nonce = token_urlsafe(NONCE_BYTES)
        await record.save(
            session,
            reason="Created new token",
        )

    return web.json_response(
        {
            "access_token": record.token,
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
            "c_nonce": record.nonce,
            # I don't think it makes sense for the two expirations to be
            # different; coordinating a new c_nonce separate from a token
            # refresh seems like a pain.
            "c_nonce_expires_in": EXPIRES_IN,
        }
    )


async def check_token(
    context: AdminRequestContext,
    bearer: Optional[str] = None,
) -> JWTVerifyResult:
    """Validate the OID4VCI token."""
    if not bearer or not bearer.lower().startswith("bearer "):
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized()
    if scheme.lower() != "bearer":
        raise web.HTTPUnauthorized()

    config = Config.from_settings(context.settings)
    profile = context.profile

    if config.auth_server_url:
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"
        auth_server_url = f"{config.auth_server_url}{get_tenant_subpath(profile)}"
        introspect_endpoint = f"{auth_server_url}/introspect"
        auth_header = await get_auth_header(
            profile, config, issuer_server_url, introspect_endpoint
        )
        resp = await AppResources.get_http_client().post(
            introspect_endpoint,
            data={"token": cred},
            headers={"Authorization": auth_header},
        )
        introspect = await resp.json()
        if not introspect.get("active"):
            raise web.HTTPUnauthorized(reason="invalid_token")
        else:
            result = JWTVerifyResult(headers={}, payload=introspect, verified=True)
            return result

    result = await jwt_verify(context.profile, cred)
    if not result.verified:
        raise web.HTTPUnauthorized()  # Invalid credentials

    if result.payload["exp"] < datetime_now().timestamp():
        raise web.HTTPUnauthorized()  # Token expired

    return result


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle proof of posession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"][0].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    if headers.get("typ") != "openid4vci-proof+jwt":
        raise web.HTTPBadRequest(reason="Invalid proof: wrong typ.")

    if "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(reason="Invalid kid") from exc
    elif "jwk" in headers:
        key = Key.from_jwk(headers["jwk"])
    elif "x5c" in headers:
        raise web.HTTPBadRequest(reason="x5c not supported")
    else:
        raise web.HTTPBadRequest(reason="No key material in proof")

    payload = b64_to_dict(encoded_payload)
    nonce = payload.get("nonce")
    if c_nonce:
        if c_nonce != nonce:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong nonce.")
    else:
        redeemed = await Nonce.redeem_by_value(profile.session(), nonce)
        if not redeemed:
            raise web.HTTPBadRequest(reason="Invalid proof: wrong or used nonce.")

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )
    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=headers.get("jwk"),
    )


def types_are_subset(request: Optional[List[str]], supported: Optional[List[str]]):
    """Compare types."""
    if request is None:
        return False
    if supported is None:
        return False
    return set(request).issubset(set(supported))
