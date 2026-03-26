"""DID JWK routes for admin API."""

import json

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import P256, KeyTypes
from acapy_agent.wallet.util import bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
)
from aries_askar import Key, KeyAlg
from marshmallow import fields
from marshmallow.validate import OneOf

from ..jwk import DID_JWK


class CreateDIDJWKRequestSchema(OpenAPISchema):
    """Request schema for creating a did:jwk."""

    key_type = fields.Str(
        required=True,
        metadata={
            "description": "Type of key",
        },
        validate=OneOf(
            [
                "ed25519",
                "p256",
            ]
        ),
    )


class CreateDIDJWKResponseSchema(OpenAPISchema):
    """Response schema for creating a did:jwk."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "The created did:jwk",
        },
    )


@docs(
    tags=["did"],
    summary="Create DID JWK.",
)
@request_schema(CreateDIDJWKRequestSchema())
@response_schema(CreateDIDJWKResponseSchema())
async def create_did_jwk(request: web.Request):
    """Route for creating a did:jwk."""

    context: AdminRequestContext = request["context"]
    body = await request.json()
    key_type = body["key_type"]
    key_types = context.inject(KeyTypes)

    async with context.session() as session:
        wallet = session.inject(BaseWallet)
        key_type_instance = key_types.from_key_type(key_type)

        if not key_type_instance:
            raise web.HTTPBadRequest(reason="Invalid key type")

        assert isinstance(session, AskarProfileSession)
        key = Key.generate(KeyAlg(key_type_instance.key_type))

        await session.handle.insert_key(
            key.get_jwk_thumbprint(),
            key,
        )
        jwk = json.loads(key.get_jwk_public())
        jwk["use"] = "sig"

        did = "did:jwk:" + bytes_to_b64(json.dumps(jwk).encode(), urlsafe=True, pad=False)

        did_info = DIDInfo(
            did=did,
            verkey=key.get_jwk_thumbprint(),
            metadata={},
            method=DID_JWK,
            key_type=P256,
        )

        await wallet.store_did(did_info)

        return web.json_response({"did": did})
