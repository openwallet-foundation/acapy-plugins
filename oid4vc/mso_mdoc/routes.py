"""mso_mdoc admin routes."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.jsonld.error import (
    BadJWSHeaderError,
    InvalidVerificationMethod,
)
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from acapy_agent.resolver.base import ResolverError
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from .mdoc import mso_mdoc_sign, mso_mdoc_verify

SPEC_URI = "https://www.iso.org/obp/ui/#iso:std:iso-iec:18013:-5:dis:ed-1:v1:en"
LOGGER = logging.getLogger(__name__)


class MdocPluginResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc Plugin."""


class MdocCreateSchema(OpenAPISchema):
    """Request schema to create a jws with a particular DID."""

    headers = fields.Dict()
    payload = fields.Dict(required=True)
    did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={"description": "DID of interest", "example": GENERIC_DID_EXAMPLE},
    )
    verification_method = fields.Str(
        data_key="verificationMethod",
        required=False,
        validate=Uri(),
        metadata={
            "description": "Information used for proof verification",
            "example": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg34"
                "2Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )


class MdocVerifySchema(OpenAPISchema):
    """Request schema to verify a mso_mdoc."""

    mso_mdoc = fields.Str(
        validate=None, metadata={"example": "a36776657273696f6e63312e..."}
    )


class MdocVerifyResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc verification result."""

    valid = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    kid = fields.Str(required=True, metadata={"description": "kid of signer"})
    headers = fields.Dict(
        required=True, metadata={"description": "Headers from verified mso_mdoc."}
    )
    payload = fields.Dict(
        required=True, metadata={"description": "Payload from verified mso_mdoc"}
    )


@docs(
    tags=["mso_mdoc"],
    summary="Creates mso_mdoc CBOR encoded binaries according to ISO 18013-5",
)
@request_schema(MdocCreateSchema)
@response_schema(MdocPluginResponseSchema(), description="")
async def mdoc_sign(request: web.BaseRequest):
    """Request handler for sd-jws creation using did.

    Args:
        request: The web request object.

            "headers": { ... },
            "payload": { ... },
            "did": "did:example:123",
            "verificationMethod": "did:example:123#keys-1"
            with did and verification being mutually exclusive.

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    did = body.get("did")
    verification_method = body.get("verificationMethod")
    headers = body.get("headers", {})
    payload = body.get("payload", {})

    try:
        mso_mdoc = await mso_mdoc_sign(
            context.profile, headers, payload, did, verification_method
        )
    except ValueError as err:
        raise web.HTTPBadRequest(reason="Bad did or verification method") from err

    return web.json_response(mso_mdoc)


@docs(
    tags=["mso_mdoc"],
    summary="Verify mso_mdoc CBOR encoded binaries according to ISO 18013-5",
)
@request_schema(MdocVerifySchema())
@response_schema(MdocVerifyResponseSchema(), 200, description="")
async def mdoc_verify(request: web.BaseRequest):
    """Request handler for mso_mdoc validation.

    Args:
        request: The web request object.

            "mso_mdoc": { ... }
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    mso_mdoc = body["mso_mdoc"]
    try:
        result = await mso_mdoc_verify(context.profile, mso_mdoc)
    except (BadJWSHeaderError, InvalidVerificationMethod) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except ResolverError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/mso_mdoc/sign", mdoc_sign),
            web.post("/mso_mdoc/verify", mdoc_verify),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "mso_mdoc",
            "description": "mso_mdoc plugin",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
