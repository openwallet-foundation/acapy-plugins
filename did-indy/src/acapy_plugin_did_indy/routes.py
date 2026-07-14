"""Routes for creating did:web."""

import logging
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import (
    RouteManager,
)
from acapy_agent.storage.base import StorageNotFoundError
from marshmallow import fields
from did_indy.ledger import TAAInfo, TaaAcceptance

from .registrar import IndyRegistrar
from .registry import IndyRegistry
from .models.taa_acceptance import TAAAcceptance, TAAAcceptanceSchema
from .taa_storage import (
    save_taa_acceptance,
    get_taa_acceptance,
    get_all_taa_acceptances,
)


LOGGER = logging.getLogger(__name__)


class CreateDIDIndyRequestSchema(OpenAPISchema):
    """Request schema for creating a did:web."""

    namespace = fields.Str(
        required=True,
        metadata={
            "description": "The ledger on which to register the new DID"
        }
    )

    nym = fields.Str(
        required=False,
        metadata={
            "description": "The nym this did will be based on; defaults to nym of public DID"
        },
    )
    ldp_vc = fields.Bool(
        required=False,
        metadata={
            "description": "Support LDP-VC issuance with this DID; defaults to False"
        },
    )
    didcomm = fields.Bool(
        required=False,
        metadata={"description": "Support DIDComm with this DID; defaults to True"},
    )
    mediation_id = fields.Str(
        required=False,
        metadata={"description": "Mediation record ID to be used in DIDComm service"},
    )


class CreateDIDResponseSchema(OpenAPISchema):
    """Response schema for creating a did:web."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "The created did:web",
        },
    )


@docs(
    tags=["did"],
    summary="Create DID Indy.",
)
@request_schema(CreateDIDIndyRequestSchema())
@response_schema(CreateDIDResponseSchema())
@tenant_authentication
async def create_new_did_indy(request: web.Request):
    """Route for creating a version 2 did for did:indy."""

    context: AdminRequestContext = request["context"]

    body = await request.json()
    namespace = body.get("namespace")
    ldp_vc = body.get("ldp_vc", False)
    didcomm = body.get("didcomm", True)
    mediation_id = body.get("mediation_id")

    if mediation_id and not didcomm:
        raise web.HTTPBadRequest(reason="mediation_id set but didcomm is not set")

    route_manager = context.inject(RouteManager)
    try:
        mediation_record = await route_manager.mediation_record_if_id(
            profile=context.profile,
            mediation_id=mediation_id,
            or_default=didcomm,
        )
    except StorageNotFoundError:
        raise web.HTTPNotFound(reason=f"No mediation record with id {mediation_id}")

    try:
        async with context.session() as session:
            registrar = session.inject(IndyRegistrar)
            did_info = await registrar.create_new_nym(
                context.profile,
                namespace=namespace,
                didcomm=didcomm,
                ldp_vc=ldp_vc,
                mediation_records=[mediation_record] if mediation_record else None,
            )
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Could not create did:indy with new nym: {str(e)}"
        )

    return web.json_response({"did": did_info.did})


@docs(
    tags=["did"],
    summary="Create DID Indy.",
)
@request_schema(CreateDIDIndyRequestSchema())
@response_schema(CreateDIDResponseSchema())
@tenant_authentication
async def create_did_indy(request: web.Request):
    """Route for creating a did:indy."""

    context: AdminRequestContext = request["context"]

    body = await request.json()
    namespace = body.get("namespace")
    nym = body.get("nym")
    ldp_vc = body.get("ldp_vc", False)
    didcomm = body.get("didcomm", True)
    mediation_id = body.get("mediation_id")

    if mediation_id and not didcomm:
        raise web.HTTPBadRequest(reason="mediation_id set but didcomm is not set")

    route_manager = context.inject(RouteManager)
    try:
        mediation_record = await route_manager.mediation_record_if_id(
            profile=context.profile,
            mediation_id=mediation_id,
            or_default=didcomm,
        )
    except StorageNotFoundError:
        raise web.HTTPNotFound(reason=f"No mediation record with id {mediation_id}")

    try:
        async with context.session() as session:
            registrar = session.inject(IndyRegistrar)
            did_info = await registrar.from_public_nym(
                context.profile,
                namespace,
                nym,
                didcomm=didcomm,
                ldp_vc=ldp_vc,
                mediation_records=[mediation_record] if mediation_record else None,
            )
    except Exception:
        raise web.HTTPInternalServerError(
            reason="Could not create did:indy from public nym"
        )

    return web.json_response({"did": did_info.did})


class GetNamespacesResponseSchema(OpenAPISchema):
    """Response schema for retrieving namespaces."""

    namespaces = fields.List(
        fields.Str(),
        required=True,
        metadata={
            "description": "List of available namespaces (ledgers)",
        },
    )


@docs(
    tags=["did-indy"],
    summary="Get available namespaces (ledgers).",
)
@response_schema(GetNamespacesResponseSchema())
@tenant_authentication
async def get_namespaces(request: web.Request):
    """Route for retrieving available namespaces (ledgers)."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.session() as session:
            registry = session.inject(IndyRegistry)
            namespaces = await registry.get_namespaces(context.profile)
    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Could not retrieve namespaces: {str(e)}"
        )

    return web.json_response({"namespaces": namespaces})


class GetTAARequestSchema(OpenAPISchema):
    """Request schema for retrieving TAA for a namespace."""

    namespace = fields.Str(
        required=True,
        metadata={
            "description": "The namespace (ledger) to get the TAA from",
        },
    )


class TAAResponseSchema(OpenAPISchema):
    """Response schema for TAA information."""

    taa_record = fields.Dict(
        required=True,
        metadata={
            "description": "Transaction Author Agreement information",
        },
    )


@docs(
    tags=["did-indy"],
    summary="Get Transaction Author Agreement for a namespace.",
)
@request_schema(GetTAARequestSchema())
@response_schema(TAAResponseSchema())
@tenant_authentication
async def get_taa(request: web.Request):
    """Route for retrieving TAA for a specific namespace."""

    context: AdminRequestContext = request["context"]

    body = await request.json()
    namespace = body.get("namespace")

    try:
        async with context.session() as session:
            registry = session.inject(IndyRegistry)
            taa_info: TAAInfo = await registry.get_taa(context.profile, namespace)

        if taa_info.taa is None:
            raise web.HTTPNotFound(reason="No TAA found for the specified namespace")

        taa_response = {}

        # Check if we've already accepted this TAA
        async with context.session() as session:
            existing_acceptance = await get_taa_acceptance(
                session, namespace, taa_info.taa.version
            )
        taa_response["namespace"] = namespace
        taa_response["taa"] = taa_info.model_dump()
        if existing_acceptance:
            taa_response["accepted"] = True
            taa_response["acceptance_mechanism"] = existing_acceptance.mechanism
            taa_response["acceptance_time"] = existing_acceptance.accepted_at
        else:
            taa_response["accepted"] = False
    except Exception as e:
        raise web.HTTPInternalServerError(reason=f"Could not retrieve TAA: {str(e)}")

    return web.json_response(taa_response)


class AcceptTAARequestSchema(OpenAPISchema):
    """Request schema for accepting a TAA."""

    taa_info = fields.Dict(
        required=True,
        metadata={
            "description": "TAA information returned from get_taa endpoint",
        },
    )
    mechanism = fields.Str(
        required=False,
        default="on_file",
        metadata={
            "description": "Acceptance mechanism; defaults to 'on_file'",
        },
    )


class AcceptTAAResponseSchema(OpenAPISchema):
    """Response schema for TAA acceptance."""

    taa_acceptance = fields.Dict(
        required=True,
        metadata={
            "description": "TAA acceptance information",
        },
    )


@docs(
    tags=["did-indy"],
    summary="Accept Transaction Author Agreement.",
)
@request_schema(AcceptTAARequestSchema())
@response_schema(AcceptTAAResponseSchema())
@tenant_authentication
async def accept_taa(request: web.Request):
    """Route for accepting a TAA."""

    context: AdminRequestContext = request["context"]

    body = await request.json()
    taa_info = body.get("taa_info")
    mechanism = body.get("mechanism")

    try:
        async with context.session() as session:
            registry = session.inject(IndyRegistry)
            taa_acceptance = await registry.accept_taa(
                context.profile, taa_info, mechanism
            )
        if not isinstance(taa_acceptance, TaaAcceptance):
            raise web.HTTPInternalServerError(reason="Invalid TAA acceptance response")
        if not isinstance(taa_info, dict):
            raise web.HTTPBadRequest(reason="Invalid TAA information format")

        # Create and store a TAA acceptance record
        taa: dict = taa_info.get("taa", {})
        namespace = body.get("namespace")
        text = taa.get("text")
        version = taa.get("version")
        digest = taa_acceptance.taaDigest
        accepted_at: int = taa_acceptance.time
        LOGGER.debug(
            "Accepting TAA for namespace '%s', version '%s'", namespace, version
        )
        LOGGER.debug("Accepting TAA with digest '%s'", digest)
        LOGGER.debug("TAA acceptance mechanism: %s", mechanism)
        LOGGER.debug("TAA acceptance time: %s", accepted_at)

        if namespace and text and version and digest:
            taa_record = TAAAcceptance(
                namespace=namespace,
                text=text,
                version=version,
                digest=digest,
                mechanism=mechanism,
                accepted_at=accepted_at,
            )

            await save_taa_acceptance(context.profile, taa_record)

    except Exception as e:
        LOGGER.error(f"Error accepting TAA: {str(e)}")
        raise web.HTTPInternalServerError(reason="Could not accept TAA")

    return web.json_response({"taa_acceptance": taa_acceptance.model_dump()})


class ListTAAAcceptancesResponseSchema(OpenAPISchema):
    """Response schema for listing TAA acceptances."""

    taa_acceptances = fields.List(
        fields.Dict(),
        required=True,
        metadata={
            "description": "List of accepted Transaction Author Agreements",
        },
    )


@docs(
    tags=["did-indy"],
    summary="List all accepted Transaction Author Agreements.",
)
@response_schema(ListTAAAcceptancesResponseSchema())
@tenant_authentication
async def list_taa_acceptances(request: web.Request):
    """Route for listing all accepted TAAs."""

    context: AdminRequestContext = request["context"]

    try:
        taa_acceptances = await get_all_taa_acceptances(context.profile)

        # Convert the objects to dictionaries for the response
        schema = TAAAcceptanceSchema()
        result = []
        for acceptance in taa_acceptances:
            result.append(schema.dump(acceptance))

    except Exception as e:
        raise web.HTTPInternalServerError(
            reason=f"Could not list TAA acceptances: {str(e)}"
        )

    return web.json_response({"taa_acceptances": result})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/did/indy/new-did", create_new_did_indy),
            web.post("/did/indy/from-nym", create_did_indy),
            web.get("/did/indy/namespaces", get_namespaces),
            web.post("/did/indy/taa", get_taa),
            web.post("/did/indy/taa/accept", accept_taa),
            web.get("/did/indy/taa/acceptances", list_taa_acceptances),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    swagger_dict = app._state.get("swagger_dict")
    if swagger_dict is not None and isinstance(swagger_dict, dict):
        # Initialize tags if they don't exist
        if "tags" not in swagger_dict:
            swagger_dict["tags"] = []

        # Check if the tag already exists
        did_tag_exists = False
        did_indy_tag_exists = False

        tags = swagger_dict.get("tags", [])
        if tags and isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict) and tag.get("name") == "did":
                    did_tag_exists = True
                if isinstance(tag, dict) and tag.get("name") == "did-indy":
                    did_indy_tag_exists = True

        if not did_tag_exists:
            tags.append(
                {
                    "name": "did",
                    "description": "DID Registration",
                }
            )

        if not did_indy_tag_exists:
            tags.append(
                {
                    "name": "did-indy",
                    "description": "DID Indy Operations",
                }
            )
