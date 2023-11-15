"""Public routes for OID4VCI."""

import logging
from os import getenv
from typing import Optional
from aries_cloudagent.core.profile import Profile
import jwt as pyjwt

from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
)
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.wallet.jwt import jwt_verify
from marshmallow import fields
from oid4vci.oid4vci.v1_0.models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential

LOGGER = logging.getLogger(__name__)
OID4VCI_ENDPOINT = getenv("OID4VCI_ENDPOINT")


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema for the /credential endpoint."""

    format = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )
    types = fields.List(
        fields.Str(),
        metadata={"description": "List of connection records"},
    )
    credentialsSubject = fields.Dict(metadata={"description": ""})
    proof = fields.Dict(metadata={"description": ""})


class TokenRequestSchema(OpenAPISchema):
    """Request schema for the /token endpoint."""

    client_id = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )


class GetTokenSchema(OpenAPISchema):
    """Schema for ..."""

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        required=True, metadata={"description": "", "example": ""}
    )
    user_pin = fields.Str(required=False)


@docs(tags=["oid4vci"], summary="Get credential issuer metadata")
# @querystring_schema(TokenRequestSchema())
async def oid_cred_issuer(request: web.Request):
    """Credential issuer metadata endpoint."""
    profile = request["context"].profile
    public_url = OID4VCI_ENDPOINT  # TODO: check for flag first

    # Wallet query to retrieve credential definitions
    tag_filter = {}  # {"type": {"$in": ["sd_jwt", "jwt_vc_json"]}}
    async with profile.session() as session:
        credentials_supported = await SupportedCredential.query(session, tag_filter)

    metadata = {
        "credential_issuer": f"{public_url}/",  # TODO: update path with wallet id
        "credential_endpoint": f"{public_url}/credential",
        "credentials_supported": [vars(cred) for cred in credentials_supported],
        # "authorization_server": f"{public_url}/auth-server",
        # "batch_credential_endpoint": f"{public_url}/batch_credential",
    }

    return web.json_response(metadata)


async def check_token(profile: Profile, auth_header: Optional[str] = None):
    """Validate the OID4VCI token."""
    if not auth_header:
        raise web.HTTPUnauthorized()  # no authentication

    scheme, cred = auth_header.split(" ")
    if scheme.lower() != "bearer" or ():
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    jwt_header = pyjwt.get_unverified_header(cred)
    if "did:key:" not in jwt_header["kid"]:
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    result = await jwt_verify(profile, cred)
    if not result.valid:
        raise web.HTTPUnauthorized()  # Invalid credentials


@docs(tags=["oid4vci"], summary="Issue a credential")
@request_schema(IssueCredentialRequestSchema())
async def issue_cred(request: web.Request):
    """Credential issuance endpoint."""
    profile = request["context"].profile
    await check_token(profile, request.headers.get("Authorization"))


async def create_did(session):
    did_methods = session.inject(DIDMethods)
    method = did_methods.from_method("key")
    key_type = ED25519
    wallet = session.inject_or(BaseWallet)
    try:
        return await wallet.create_local_did(method=method, key_type=key_type)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@querystring_schema(GetTokenSchema())
async def get_token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""
    grant_type = request.query.get("grant_type")
    pre_authorized_code = request.query.get("pre_authorized_code")
    # user_pin = request.query.get("user_pin")
    context = request["context"]
    ex_record = None
    sup_cred_record = None
    try:
        async with context.profile.session() as session:
            filter = {
                "code": pre_authorized_code,
                # "user_pin": user_pin
            }
            records = await OID4VCIExchangeRecord.query(session, filter)
            ex_record: OID4VCIExchangeRecord = records[0]
            if not ex_record or not ex_record.code:  # TODO: check pin
                return {}  # TODO: report failure?

            if ex_record.supported_cred_id:
                sup_cred_record: SupportedCredential = (
                    await SupportedCredential.retrieve_by_id(
                        session, ex_record.supported_cred_id
                    )
                )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    scopes = sup_cred_record.scope
    exchange_id = ex_record.exchange_id
    # TODO: get valid parameters from exchange record, exchange record should have a
    # registration information along with credential claims.
    payload = {
        "scope": f"openid profile email {scopes}",
        "name": "John",
        "preferred_username": "Terry",
        "given_name": "Berry",
        "email": "ted@example.com",
    }
    signing_did = await create_did()
    try:
        jws = await jwt_sign(
            context.profile,
            headers,
            payload,
            signing_did,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(reason="Bad did or verification method") from err
    except WalletNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    nonce = token_urlsafe(16)
    # redis_conn.set(nonce, exchange_id)  # TODO: storing exchange_id is a smell
    # redis_conn.set(jwt, exchange_id)  # TODO: think of a better data structure


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/.well-known/openid-credential-issuer",
                oid_cred_issuer,
                allow_head=False,
            ),
            # TODO add .well-known/oauth-authorization-server
            # TODO add .well-known/openid-configuration
            web.post("/draft-13/credential", issue_cred),
            web.post("/draft-11/credential", issue_cred),
            web.post("/draft-13/token", get_token),
            web.post("/draft-11/token", get_token),
        ]
    )
