"""DID Webvh routes module."""

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.resolver.routes import ResolutionResultSchema
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, request_schema, response_schema
from marshmallow import fields

from .did.endorsement_manager import EndorsementManager
from .did.exceptions import (
    ConfigurationError,
    DidCreationError,
    DidUpdateError,
    EndorsementError,
)
from .did.operations_manager import DidWebvhOperationsManager


class WebvhCreateSchema(OpenAPISchema):
    """Request model for creating a Webvh DID."""

    class CreateOptionsSchema(OpenAPISchema):
        """Options for a Webvh DID request."""

        class ParametersSchema(OpenAPISchema):
            """Parameters for a Webvh DID request."""

            prerotation = fields.Bool(
                required=False,
                metadata={
                    "description": "Prerotation flag",
                    "example": False,
                },
                default=False,
            )
            portable = fields.Bool(
                required=False,
                metadata={
                    "description": "Portable flag",
                    "example": False,
                },
                default=False,
            )

        namespace = fields.Str(
            required=True,
            metadata={
                "description": "Namespace for the DID",
                "example": "prod",
            },
        )
        identifier = fields.Str(
            required=False,
            metadata={
                "description": "Identifier for the DID. Must be unique within the "
                "namespace. If not provided, a random one will be generated.",
                "example": "1",
            },
        )
        parameters = fields.Nested(ParametersSchema())

    options = fields.Nested(CreateOptionsSchema())


class WebvhDeactivateSchema(OpenAPISchema):
    """Request model for deactivating a Webvh DID."""

    id = fields.Str(
        required=True,
        metadata={
            "description": "ID of the DID to deactivate",
            "example": "did:webvh:prod:1",
        },
    )


class IdRequestParamSchema(OpenAPISchema):
    """Request model for creating a Webvh DID."""

    entry_id = fields.Str(
        required=True,
        metadata={
            "description": "ID of the DID to endorse",
            "example": "did:webvh:prod:1",
        },
    )


@docs(tags=["did"], summary="Create a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def create(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).create(
                options=request["data"]["options"]
            )
        )
    except (DidCreationError, EndorsementError, ConfigurationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Update a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def update(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]
    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).update(
                request["data"]["options"], request["data"].get("features", {})
            )
        )
    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Deactivate a did:webvh")
@request_schema(WebvhDeactivateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def deactivate(request: web.BaseRequest):
    """Deactivate a Webvh DID."""
    context: AdminRequestContext = request["context"]
    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).deactivate(
                request["data"]["options"]
            )
        )

    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Get all pending log entry endorsements")
@tenant_authentication
async def endorser_get_pending(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]
    return web.json_response(await EndorsementManager(context.profile).get_pending())


@docs(tags=["did"], summary="Endorse a log entry")
@querystring_schema(IdRequestParamSchema())
@tenant_authentication
async def endorse_log_entry(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]

    try:
        entry_id = request.query.get("entry_id")
        return web.json_response(
            await EndorsementManager(context.profile).endorse_entry(entry_id)
        )
    except EndorsementError as err:
        return web.json_response({"status": "error", "message": str(err)})


def register_events(event_bus: EventBus):
    """Register to the acapy startup event."""
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the endorsement setup."""

    await EndorsementManager(profile).auto_endorsement_setup()


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes([web.post("/did/webvh/create", create)])
    app.add_routes([web.post("/did/webvh/update", update)])
    app.add_routes([web.post("/did/webvh/deactivate", deactivate)])
    app.add_routes([web.post("/did/webvh/endorsement/pending", endorser_get_pending)])
    app.add_routes([web.post("/did/webvh/endorsement/endorse", endorse_log_entry)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "did",
            "description": "Endpoints for managing webvh dids",
            "externalDocs": {
                "description": "Specification",
                "url": "https://www.w3.org/TR/did-core/",
            },
        }
    )
