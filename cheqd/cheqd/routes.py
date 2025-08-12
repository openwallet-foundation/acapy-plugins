"""DID Cheqd routes."""

from http import HTTPStatus

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.ledger.base import EndpointType
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.routes import (
    DIDEndpointWithTypeSchema,
    DIDSchema,
    WalletModuleResponseSchema,
)
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import Schema, fields

from .did.manager import CheqdDIDManager, CheqdDIDManagerError
from .validation import (
    CHEQD_DID_EXAMPLE,
    CHEQD_DID_VALIDATE,
    CHEQD_DIDSTATE_EXAMPLE,
)


class CustomDIDEndpointWithTypeSchema(DIDEndpointWithTypeSchema):
    """Schema for setting Cheqd DID endpoint with type."""

    did = fields.Str(
        required=True,
        validate=CHEQD_DID_VALIDATE,
        metadata={"description": "DID of interest", "example": CHEQD_DID_EXAMPLE},
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
    serviceEndpoint = fields.Str(
        required=True, metadata={"description": "Service endpoint URL"}
    )
    recipientKeys = fields.List(
        fields.Str(metadata={"description": "Did key reference"}),
        required=True,
        metadata={
            "description": "Array of did key references to denote the default recipients"
        },
    )
    priority = fields.Integer(
        required=False, metadata={"description": "Priority of the service endpoint"}
    )
    routingKeys = fields.List(
        fields.Str(metadata={"description": "Did key reference"}),
        required=False,
        metadata={
            "description": "Array of did key references to denote individual routing hops"
        },
    )
    accept = fields.List(
        fields.Str(metadata={"description": "Media types"}),
        required=False,
        metadata={"description": "Array of supported media types"},
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


class CreateCheqdDIDRequestSchema(OpenAPISchema):
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


class CreateCheqdDIDResponseSchema(OpenAPISchema):
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


class DeactivateCheqdDIDRequestSchema(OpenAPISchema):
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


class DeactivateCheqdDIDResponseSchema(OpenAPISchema):
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
            "description": "DID that has been deactivated",
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


class UpdateCheqdDIDRequestSchema(OpenAPISchema):
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


class UpdateCheqdDIDResponseSchema(OpenAPISchema):
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


class DIDImportSchema(OpenAPISchema):
    """Request schema for importing a DID."""

    did_document = fields.Raw(
        required=True,
        metadata={
            "description": "The DID document to import",
            "example": {
                "id": "did:example:123456789",
                "verificationMethod": [
                    {
                        "id": "did:example:123456789#key-1",
                        "type": "Ed25519VerificationKey2018",
                        "controller": "did:example:123456789",
                        "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
                    }
                ],
            },
        },
    )

    metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Additional metadata to associate with the imported DID"
        },
    )


class DIDImportResponseSchema(OpenAPISchema):
    """Response schema for DID import."""

    result = fields.Nested(DIDSchema())


@docs(tags=["did"], summary="Create a did:cheqd")
@request_schema(CreateCheqdDIDRequestSchema())
@response_schema(CreateCheqdDIDResponseSchema, HTTPStatus.OK)
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
@request_schema(UpdateCheqdDIDRequestSchema())
@response_schema(UpdateCheqdDIDResponseSchema, HTTPStatus.OK)
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
@request_schema(DeactivateCheqdDIDRequestSchema())
@response_schema(DeactivateCheqdDIDResponseSchema, HTTPStatus.OK)
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


@docs(
    tags=["wallet"], summary="Update the endpoint in the wallet and on ledger if posted"
)
@request_schema(CustomDIDEndpointWithTypeSchema)
@response_schema(WalletModuleResponseSchema, 200, description="")
@tenant_authentication
async def cheqd_wallet_set_did_endpoint(request: web.BaseRequest):
    """Set the endpoint for a did:cheqd DID."""
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
        did = body.get("did")
        endpoint = body.get("endpoint")
        endpoint_type = EndpointType.get(
            body.get("endpoint_type", EndpointType.ENDPOINT.w3c)
        )

        # Use the DIDManager to update the DID with the new endpoint
        cheqd_manager = CheqdDIDManager(context.profile, registrar_url, resolver_url)
        result = await cheqd_manager.set_did_endpoint(
            did,
            endpoint,
            endpoint_type,
        )

        return web.json_response({"result": result})

    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err))


@docs(
    tags=["did"],
    summary="Import an existing DID into the wallet",
)
@request_schema(DIDImportSchema)
@response_schema(DIDImportResponseSchema(), description="")
@tenant_authentication
async def import_did(request: web.BaseRequest):
    """Request handler for importing a DID into the wallet.

    Args:
        request: aiohttp request object

    Returns:
        The imported DID information

    """
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
        ).import_did(
            body.get("did_document"),
            body.get("metadata"),
        )
    except CheqdDIDManagerError as err:
        raise web.HTTPInternalServerError(reason=err.roll_up)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)

    return web.json_response(result)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/did/cheqd/create", create_cheqd_did),
            web.post("/did/cheqd/update", update_cheqd_did),
            web.post("/did/cheqd/deactivate", deactivate_cheqd_did),
            web.post("/did/import", import_did),
            # Add a cheqd specific set-did-endpoint route with our custom handler
            web.post("/wallet/cheqd/set-did-endpoint", cheqd_wallet_set_did_endpoint),
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
