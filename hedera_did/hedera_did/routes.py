"""Hedera API Routes."""

import logging
from typing import Mapping

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from aiohttp import web
from aiohttp_apispec import docs, json_schema, response_schema
from did_sdk_py.did.hedera_did_resolver import HederaDid
from hedera import PrivateKey
from marshmallow import fields
from marshmallow.validate import OneOf

from .client import get_client_provider
from .config import Config
from .did_method import HEDERA


LOGGER = logging.getLogger(__name__)

class HederaRequestJSONSchema(OpenAPISchema):
    """Request schema."""

    key_type = fields.String(
            required=True,
            validate=OneOf(
                [
                    "Ed25519"
                ]
            ),
            metadata={
                "description": "Key type to use for DID registration",
                "example": "Ed25519"
                }
            )

    seed= fields.String(
            required=False,
            metadata={
                "description": "Optional seed to use for DID",
                "example": "000000000000000000000000Trustee1"
                }
            )

class HederaResponseSchema(OpenAPISchema):
    """Response schema."""

    did = fields.Str(
            required=True,
            metadata={
                "description": "DID that was created",
                "example": "did:hedera:testnet:zMqXmB7cTsTXqyxDPBbrgu5EPqw61kouK1qjMvnoPa96_0.0.5254964"  # noqa: E501
                }
            )

    verkey = fields.Str(
            required=True,
            metadata={
                "description": "Verification key",
                "example": "7mbbTXhnPx8ux4LBVRPoHxpSACPRF9axYU4uwiKNhzUH"
                }
            )

    key_type = fields.Str(
            required=True,
            metadata={
                "description": "Used key type",
                "example": "ed25519"
                }
            )

@docs(
    tags=["hedera"],
    summary="Register a new DID",
)
@json_schema(HederaRequestJSONSchema())
@response_schema(HederaResponseSchema(), 200)
@tenant_authentication
async def hedera_register_did(request: web.BaseRequest):
    """Request handler for registering a new DID."""
    LOGGER.debug("Received register new DID")

    context: AdminRequestContext = request["context"]

    body = await request.json()

    key_type = body["key_type"]
    seed = body.get("seed") or None

    if key_type != "Ed25519":
        raise web.HTTPForbidden(reason=(f"Unsupported key type {key_type}"))

    async with context.session() as session:
       key_types = session.inject_or(KeyTypes)

       if not key_types:
         raise web.HTTPForbidden(reason="No key types available")

       key_type = key_types.from_key_type(body.get("key_type", "Ed25519")) or ED25519

       wallet = session.inject_or(BaseWallet)

       if not wallet:
         raise web.HTTPForbidden(reason="No wallet available")

       key_info = await wallet.create_key(ED25519, seed=seed)

       key_entry = await wallet._session.handle.fetch_key(name=key_info.verkey)

       if not key_entry:
           raise Exception("Could not fetch key")

       key = key_entry.key

       private_key_bytes = key.get_secret_bytes()

       private_key_der = PrivateKey.fromBytes(private_key_bytes).toStringDER()

       config = Config.from_settings(context.settings)

       network = config.network
       operator_id = config.operator_id
       operator_key_der = config.operator_key_der

       client_provider = get_client_provider(
               network,
               operator_id,
               operator_key_der
               )

       hedera_did = HederaDid(
               client_provider,
               private_key_der=private_key_der
               )

       await hedera_did.register()

       did = hedera_did.identifier

       info = {
               "did": did,
               "verkey": key_info.verkey,
               "key_type": key_type.key_type
               }

       await wallet._session.handle.insert(
            "did",
            did,
            value_json={
                "did": did,
                "method": HEDERA.method_name,
                "verkey": key_info.verkey,
                "verkey_type": key_type.key_type,
                "metadata": {}
                },
            tags={
                "method": HEDERA.method_name,
                "verkey": key_info.verkey,
                "verkey_type": key_type.key_type,
                }
           )

    return web.json_response(info)


async def register(app: web.Application):
    """Register endpoints."""
    app.add_routes([web.post("/hedera/did/register", hedera_register_did)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    app_state: Mapping = app._state

    if "tags" not in app_state["swagger_dict"]:
        app_state["swagger_dict"]["tags"] = []

    app_state["swagger_dict"]["tags"].append(
        {
            "name": "Hedera",
            "description": "Hedera plugin API",
            "externalDocs": {"description": "Specification", "url": "https://github.com/hashgraph/did-method/blob/master/hedera-did-method-specification.md"},
        }
    )
