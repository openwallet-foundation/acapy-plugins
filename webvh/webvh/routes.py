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

from .config.config import set_config
from .did.exceptions import (
    ConfigurationError,
    DidCreationError,
    DidUpdateError,
    WitnessError,
)
from .did.operations_manager import DidWebvhOperationsManager
from .did.witness_manager import WitnessManager


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
            "description": "ID of the DID to attest",
            "example": "did:web:server.localhost%3A8000:prod:1",
        },
    )


class ConfigureWebvhSchema(OpenAPISchema):
    """Request model for creating a Webvh DID."""

    server_url = fields.Str(
        required=True,
        metadata={
            "description": "URL of the webvh server",
            "example": "http://localhost:8000",
        },
    )
    witness = fields.Boolean(
        required=False,
        metadata={
            "description": "Enable the witness role",
            "example": "false",
        },
        default=False,
    )
    witness_key = fields.Str(
        required=False,
        metadata={
            "description": "Existing key to use as witness key",
            "example": "z6MkwHAfotoRgkYeS4xDMSMQdQfiTHsmKq82qudwcD5YdCo9",
        },
    )
    auto_attest = fields.Bool(
        required=False,
        metadata={
            "description": "Auto sign witness requests",
            "example": "false",
        },
        default=False,
    )
    witness_invitation = fields.Str(
        required=False,
        metadata={
            "description": "An invitation from a witness",
            "example": "http://localhost:3000?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJlMzI5OGIyNS1mZjRlLTRhZmItOTI2Yi03ZDcyZmVlMjQ1ODgiLCAibGFiZWwiOiAid2VidmgtZW5kb3JzZXIiLCAiaGFuZHNoYWtlX3Byb3RvY29scyI6IFsiaHR0cHM6Ly9kaWRjb21tLm9yZy9kaWRleGNoYW5nZS8xLjAiXSwgInNlcnZpY2VzIjogW3siaWQiOiAiI2lubGluZSIsICJ0eXBlIjogImRpZC1jb21tdW5pY2F0aW9uIiwgInJlY2lwaWVudEtleXMiOiBbImRpZDprZXk6ejZNa3FDQ1pxNURSdkdMcDV5akhlZlZTa2JhN0tYWlQ1Nld2SlJacEQ2Z3RvRzU0I3o2TWtxQ0NacTVEUnZHTHA1eWpIZWZWU2tiYTdLWFpUNTZXdkpSWnBENmd0b0c1NCJdLCAic2VydmljZUVuZHBvaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9XX0",
        },
    )


@docs(tags=["did"], summary="Create a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def create(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).create(
                options=request_json["options"]
            )
        )
    except (DidCreationError, WitnessError, ConfigurationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Update a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def update(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).update(
                request_json["options"], request_json.get("features", {})
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
    request_json = await request.json()
    try:
        return web.json_response(
            await DidWebvhOperationsManager(context.profile).deactivate(
                request_json["options"]
            )
        )

    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Get all pending log entry attestations")
@tenant_authentication
async def witness_get_pending(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]
    pending_requests = await WitnessManager(
        context.profile
    ).get_pending_did_request_docs()
    return web.json_response({"results": pending_requests})


@docs(tags=["did"], summary="Attest a log entry")
@querystring_schema(IdRequestParamSchema())
@tenant_authentication
async def attest_log_entry(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]

    try:
        entry_id = request.query.get("entry_id")
        return web.json_response(
            await WitnessManager(context.profile).attest_did_request_doc(entry_id)
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did"], summary="Configure a webvh agent")
@request_schema(ConfigureWebvhSchema)
@tenant_authentication
async def configure(request: web.BaseRequest):
    """Configure a webvh agent."""
    profile = request["context"].profile

    # Build the config object
    config = {}

    request_json = await request.json()

    config["server_url"] = request_json.get("server_url")

    if not config.get("server_url"):
        raise ConfigurationError("No server url provided.")

    config["role"] = "witness" if request_json.get("witness") else "controller"

    if config["role"] == "witness":
        config["auto_attest"] = request_json.get("auto_attest")

    if config["role"] == "controller":
        config["witness_invitation"] = request_json.get("witness_invitation")

    try:
        await set_config(profile, config)

        if config["role"] == "witness":
            witness_key = await WitnessManager(profile).setup_witness_key(
                request_json.get("witness_key")
            )
            if not witness_key:
                raise ConfigurationError("No witness key set.")
            return web.json_response({"witness_key": witness_key})

        await WitnessManager(profile).auto_witness_setup()

        return web.json_response({"status": "success"})

    except ConfigurationError as err:
        return web.json_response({"status": "error", "message": str(err)})


def register_events(event_bus: EventBus):
    """Register to the acapy startup event."""
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the witness setup."""
    if not profile.settings.get("multitenant.enabled"):
        await WitnessManager(profile).auto_witness_setup()


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes([web.post("/did/webvh/create", create)])
    app.add_routes([web.post("/did/webvh/update", update)])
    app.add_routes([web.post("/did/webvh/deactivate", deactivate)])
    app.add_routes([web.post("/did/webvh/witness/attest", attest_log_entry)])
    app.add_routes(
        [web.get("/did/webvh/witness/pending", witness_get_pending, allow_head=False)]
    )
    app.add_routes([web.post("/did/webvh/configuration", configure)])


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
