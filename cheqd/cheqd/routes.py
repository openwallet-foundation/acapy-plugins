"""DID Cheqd routes."""

from http import HTTPStatus

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.error import WalletError
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import Schema, fields

from .did.manager import CheqdDIDManager, CheqdDIDManagerError
from .validation import (
    CHEQD_DID_EXAMPLE,
    CHEQD_DID_VALIDATE,
    CHEQD_DIDSTATE_EXAMPLE,
)


class VerificationMethodSchema(Schema):
    """VerificationMethod Schema."""

    id = fields.Str(
        required=True,
        metadata={
            "description": "Verification Method ID",
            "example": "did:example:123#key-1",
        },
    )
    type = fields.Str(
        required=True,
        metadata={
            "description": "Type of Verification Method",
            "example": "Ed25519VerificationKey2018",
        },
    )
    publicKeyMultibase = fields.Str(
        required=False,
        metadata={"description": "Public Key in multibase format", "example": "z6Mk..."},
    )
    publicKeyBase58 = fields.Str(
        required=False,
        metadata={
            "description": "Public Key in base58 format",
            "example": "B12NYF8RZ5Zk..",
        },
    )
    publicKeyJwk = fields.Dict(
        required=False,
        metadata={
            "description": "Public Key in Jwk format",
            "example": {"kty": "OKP", "crv": "Ed25519", "x": "G6t3iUB8..."},
        },
    )
    controller = fields.Str(
        required=True,
        metadata={"description": "Verification controller DID"},
    )


class ServiceSchema(Schema):
    """Service Schema."""

    id = fields.Str(
        required=True,
        metadata={"description": "Service ID", "example": "did:example:123#service-1"},
    )
    type = fields.Str(
        required=True,
        metadata={"description": "Service Type", "example": "MessagingService"},
    )
    serviceEndpoint = fields.List(
        fields.Str(metadata={"description": "Service endpoint URL"}),
        required=True,
        metadata={"description": "Array of Service endpoints"},
    )


class DIDDocumentSchema(Schema):
    """DIDDocument Schema."""

    id = fields.Str(
        required=True, metadata={"description": "DID ID", "example": "did:example:123"}
    )
    controller = fields.List(
        fields.Str,
        required=True,
        metadata={"description": "DID Document controllers"},
    )
    verificationMethod = fields.List(
        fields.Nested(VerificationMethodSchema),
        required=True,
        metadata={"description": "Verification Methods"},
    )
    authentication = fields.List(
        fields.Str, required=True, metadata={"description": "Authentication Methods"}
    )
    assertionMethod = fields.List(
        fields.Str, required=False, metadata={"description": "Assertion Methods"}
    )
    service = fields.List(
        fields.Nested(ServiceSchema), required=False, metadata={"description": "Services"}
    )


class CreateRequestSchema(OpenAPISchema):
    """Parameters and validators for create DID endpoint."""

    options = fields.Dict(
        required=False,
        metadata={
            "description": "Additional configuration options",
            "example": {
                "network": "testnet",
                "method_specific_id_algo": "uuid",
                "key_type": "ed25519",
            },
        },
    )
    features = fields.Dict(
        required=False,
        metadata={
            "description": "Additional features to enable for the did.",
            "example": "{}",
        },
    )


class CreateResponseSchema(OpenAPISchema):
    """Response schema for create DID endpoint."""

    success = fields.Bool(
        metadata={
            "description": "Flag to denote if the operation was successful",
            "example": True,
        }
    )
    did = fields.Str(
        metadata={
            "description": "DID created",
            "example": CHEQD_DID_EXAMPLE,
        }
    )
    verkey = fields.Str(
        metadata={
            "description": "Verification key",
            "example": "BnSWTUQmdYCewSGFrRUhT6LmKdcCcSzRGqWXMPnEP168",
        }
    )
    didState = fields.Dict(
        metadata={
            "description": "The published didState",
            "example": CHEQD_DIDSTATE_EXAMPLE,
        }
    )


class DeactivateRequestSchema(OpenAPISchema):
    """Parameters and validators for deactivate DID endpoint."""

    did = fields.Str(
        required=True,
        validate=CHEQD_DID_VALIDATE,
        metadata={"description": "DID to deactivate", "example": CHEQD_DID_EXAMPLE},
    )
    options = fields.Dict(
        required=False,
        metadata={
            "description": "Additional configuration options",
            "example": {"network": "testnet"},
        },
    )


class DeactivateResponseSchema(OpenAPISchema):
    """Response schema for deactivate DID endpoint."""

    success = fields.Bool(
        metadata={
            "description": "Flag to denote if the operation was successful",
            "example": True,
        }
    )
    did = fields.Str(
        validate=CHEQD_DID_VALIDATE,
        metadata={
            "description": "DID that has been deactivted",
            "example": CHEQD_DID_EXAMPLE,
        },
    )
    didState = fields.Str(
        required=True,
        metadata={
            "description": "State of the did update",
            "example": CHEQD_DIDSTATE_EXAMPLE,
        },
    )


class UpdateRequestSchema(OpenAPISchema):
    """Parameters and validators for update DID endpoint."""

    did = fields.Str(
        required=True,
        validate=CHEQD_DID_VALIDATE,
        metadata={
            "description": "DID to update",
            "example": CHEQD_DID_EXAMPLE,
        },
    )
    options = fields.Dict(
        required=False,
        metadata={
            "description": "Additional configuration options",
            "example": {"network": "testnet"},
        },
    )
    didDocument = fields.Nested(
        DIDDocumentSchema,
        required=True,
        metadata={
            "description": "DID Document to update",
            "example": {
                "id": CHEQD_DID_EXAMPLE,
                "controller": [CHEQD_DID_EXAMPLE],
                "verificationMethod": [
                    {
                        "id": CHEQD_DID_EXAMPLE + "#key-1",
                        "type": "Ed25519VerificationKey2018",
                        "controller": CHEQD_DID_EXAMPLE,
                        "publicKeyMultibase": "z6Mk...",
                    }
                ],
                "authentication": [CHEQD_DID_EXAMPLE + "#key-1"],
                "service": [
                    {
                        "id": CHEQD_DID_EXAMPLE + "#service-1",
                        "type": "MessagingService",
                        "serviceEndpoint": ["https://example.com/service"],
                    }
                ],
            },
        },
    )


class UpdateResponseSchema(OpenAPISchema):
    """Response schema for update DID endpoint."""

    success = fields.Bool(
        metadata={
            "description": "Flag to denote if the operation was successful",
            "example": True,
        }
    )
    did = fields.Str(
        validate=CHEQD_DID_VALIDATE,
        metadata={
            "description": "DID that has been updated",
            "example": CHEQD_DID_EXAMPLE,
        },
    )
    didState = fields.Str(
        required=True,
        metadata={
            "description": "State of the did update",
            "example": CHEQD_DIDSTATE_EXAMPLE,
        },
    )


@docs(tags=["did"], summary="Create a did:cheqd")
@request_schema(CreateRequestSchema())
@response_schema(CreateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def create_cheqd_did(request: web.BaseRequest):
    """Create a Cheqd DID."""
    context: AdminRequestContext = request["context"]
    config = context.settings.get("plugin_config")
    resolver_url = None
    registrar_url = None
    if config:
        registrar_url = config.get("registrar_url")
        resolver_url = config.get("resolver_url")
    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = await CheqdDIDManager(
            context.profile, registrar_url, resolver_url
        ).create(body.get("didDocument"), body.get("options"))
        return web.json_response(
            {"did": result.get("did"), "verkey": result.get("verkey")}
        )
    except CheqdDIDManagerError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)


@docs(tags=["did"], summary="Update a did:cheqd")
@request_schema(UpdateRequestSchema())
@response_schema(UpdateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def update_cheqd_did(request: web.BaseRequest):
    """Update a Cheqd DID."""
    context: AdminRequestContext = request["context"]
    config = context.settings.get("plugin_config")
    resolver_url = None
    registrar_url = None
    if config:
        registrar_url = config.get("registrar_url")
        resolver_url = config.get("resolver_url")
    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = await CheqdDIDManager(
            context.profile, registrar_url, resolver_url
        ).update(
            body.get("did"),
            body.get("didDocument"),
            body.get("options"),
        )
        return web.json_response(result)
    except CheqdDIDManagerError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)


@docs(tags=["did"], summary="Deactivate a did:cheqd")
@request_schema(DeactivateRequestSchema())
@response_schema(DeactivateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def deactivate_cheqd_did(request: web.BaseRequest):
    """Deactivate a Cheqd DID."""
    context: AdminRequestContext = request["context"]
    config = context.settings.get("plugin_config")
    resolver_url = None
    registrar_url = None
    if config:
        registrar_url = config.get("registrar_url")
        resolver_url = config.get("resolver_url")
    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = await CheqdDIDManager(
            context.profile, registrar_url, resolver_url
        ).deactivate(body.get("did"))
        return web.json_response(result)
    except CheqdDIDManagerError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/did/cheqd/create", create_cheqd_did),
            web.post("/did/cheqd/update", update_cheqd_did),
            web.post("/did/cheqd/deactivate", deactivate_cheqd_did),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "did",
            "description": "Endpoints for managing dids",
            "externalDocs": {
                "description": "Specification",
                "url": "https://www.w3.org/TR/did-core/",
            },
        }
    )
