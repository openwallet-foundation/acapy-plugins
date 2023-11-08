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
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.wallet.jwt import jwt_verify
from marshmallow import fields
from .models.cred_sup_record import OID4VCICredentialSupported

LOGGER = logging.getLogger(__name__)
OID4VCI_ENDPOINT = getenv("OID4VCI_ENDPOINT")
assert OID4VCI_ENDPOINT


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


@docs(tags=["oid4vci"], summary="Get credential issuer metadata")
# @querystring_schema(TokenRequestSchema())
async def oid_cred_issuer(request: web.Request):
    """Credential issuer metadata endpoint."""
    profile = request["context"].profile
    public_url = OID4VCI_ENDPOINT  # TODO: check for flag first

    # Wallet query to retrieve credential definitions
    tag_filter = {"type": {"$in": ["sd_jwt", "jwt_vc_json"]}}
    async with profile.session() as session:
        credentials_supported = await OID4VCICredentialSupported.query(
            session, tag_filter
        )

    metadata = {
        "credential_issuer": f"{public_url}/",  # TODO: update path with wallet id
        "credential_endpoint": f"{public_url}/credential",
        "credentials_supported": [cred.serialize() for cred in credentials_supported],
        "authorization_server": f"{public_url}/auth-server",
        "batch_credential_endpoint": f"{public_url}/batch_credential",
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


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@querystring_schema(TokenRequestSchema())
async def get_token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/.well-known/openid-credential-issuer",
                oid_cred_issuer,
                allow_head=False,
            ),
            # web.get("/auth-server/.well-known/oauth-authorization-server", self., allow_head=False),
            # web.get("/auth-server/.well-known/openid-configuration", self., allow_head=False),
            web.post("/draft-13/credential", issue_cred),
            web.post("/draft-11/credential", issue_cred),
            web.post("/draft-13/token", get_token),
            web.post("/draft-11/token", get_token),
        ]
    )
