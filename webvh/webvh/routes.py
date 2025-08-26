"""DID Webvh routes module."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN
from acapy_agent.resolver.routes import ResolutionResultSchema
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.keys.manager import MultikeyManagerError
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, request_schema, response_schema
from marshmallow.exceptions import ValidationError

from .config.config import get_plugin_config
from .did.manager import ControllerManager
from .did.exceptions import (
    ConfigurationError,
    DidCreationError,
    DidUpdateError,
    OperationError,
    WitnessError,
)
from .did.models.operations import (
    ConfigureWebvhSchema,
    WebvhAddVMSchema,
    WebvhCreateSchema,
    WebvhCreateWitnessInvitationSchema,
    WebvhDeactivateSchema,
    WebvhSCIDQueryStringSchema,
    WebvhUpdateWhoisSchema,
)
from .did.witness import WitnessManager
from .protocols.log_entry.routes import (
    get_pending_log_entries,
    approve_pending_log_entry,
    reject_pending_log_entry,
)
from .protocols.attested_resource.routes import (
    get_pending_attested_resources,
    approve_pending_attested_resource,
    reject_pending_attested_resource,
)

LOGGER = logging.getLogger(__name__)


@docs(tags=["did-webvh"], summary="Get webvh agent configuration")
@tenant_authentication
async def get_config(request: web.BaseRequest):
    """Get webvh agent configuration."""
    return web.json_response(await get_plugin_config(request["context"].profile))


@docs(tags=["did-webvh"], summary="Configure a webvh agent")
@request_schema(ConfigureWebvhSchema)
@tenant_authentication
async def configure(request: web.BaseRequest):
    """Configure a webvh agent."""
    profile = request["context"].profile
    request_json = await request.json()

    try:
        return web.json_response(await ControllerManager(profile).configure(request_json))

    except (ConfigurationError, OperationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Create a witness invitation")
@request_schema(WebvhCreateWitnessInvitationSchema)
@tenant_authentication
async def witness_create_invite(request: web.BaseRequest):
    """Create a witness invitation."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await WitnessManager(context.profile).create_invitation(
                request_json.get("alias"),
                request_json.get("label"),
                request_json.get("multi"),
            )
        )
    except (StorageNotFoundError, ValidationError, WitnessError) as e:
        raise web.HTTPBadRequest(reason=e.roll_up)


@docs(tags=["did-webvh"], summary="Create a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def create(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await ControllerManager(context.profile).create(
                options=request_json["options"]
            )
        )
    except (DidCreationError, WitnessError, ConfigurationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Update a did:webvh")
@querystring_schema(WebvhSCIDQueryStringSchema())
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def update(request: web.BaseRequest):
    """Update a Webvh log."""
    context: AdminRequestContext = request["context"]
    try:
        return web.json_response(
            await ControllerManager(context.profile).update(request.query.get("scid"))
        )

    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Add verification method")
@querystring_schema(WebvhSCIDQueryStringSchema())
@request_schema(WebvhAddVMSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def add_verification_method_request(request: web.BaseRequest):
    """Add a Webvh Verification Method."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()

    scid = request.query.get("scid")
    key_type = request_json.get("type") or "Multikey"
    relationships = request_json.get("relationships") or []

    try:
        did_document = await ControllerManager(context.profile).add_verification_method(
            scid=scid,
            key_type=key_type,
            relationships=relationships,
            key_id=request_json.get("id"),
            multikey=request_json.get("multikey"),
        )
        return web.json_response(
            await ControllerManager(context.profile).update(
                scid=scid, did_document=did_document
            )
        )
    except (DidUpdateError, MultikeyManagerError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Delete verification method")
@querystring_schema(WebvhSCIDQueryStringSchema())
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def delete_verification_method_request(request: web.BaseRequest):
    """Delete a Webvh Verification Method."""
    context: AdminRequestContext = request["context"]
    try:
        return web.json_response(
            await ControllerManager(context.profile).remove_verification_method(
                request.query.get("scid"), request.match_info["key_id"]
            )
        )
    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Deactivate a did:webvh")
@request_schema(WebvhDeactivateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def deactivate(request: web.BaseRequest):
    """Deactivate a Webvh DID."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await ControllerManager(context.profile).deactivate(request_json["options"])
        )

    except DidUpdateError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Update WHOIS linked VP")
@querystring_schema(WebvhSCIDQueryStringSchema())
@request_schema(WebvhUpdateWhoisSchema())
@tenant_authentication
async def update_whois(request: web.BaseRequest):
    """Update WHOIS linked VP."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    try:
        return web.json_response(
            await ControllerManager(context.profile).update_whois(
                request.query.get("scid"),
                request_json.get("presentation"),
                request_json.get("options", {}),
            )
        )

    except OperationError as err:
        return web.json_response({"status": "error", "message": str(err)})


def register_events(event_bus: EventBus):
    """Register to the acapy startup event."""
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the witness setup."""
    if not profile.settings.get("multitenant.enabled"):
        await ControllerManager(profile).auto_witness_setup()


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes(
        [
            web.post("/did/webvh/configuration", configure),
            web.get("/did/webvh/configuration", get_config, allow_head=False),
            web.post("/did/webvh/create", create),
            web.post("/did/webvh/update", update),
            web.post("/did/webvh/deactivate", deactivate),
            web.post(
                "/did/webvh/verification-methods",
                add_verification_method_request,
            ),
            web.delete(
                "/did/webvh/verification-methods/{key_id}",
                delete_verification_method_request,
            ),
            web.post("/did/webvh/whois", update_whois),
            web.post("/did/webvh/witness-invitation", witness_create_invite),
            web.get(
                "/did/webvh/witness/log-entries",
                get_pending_log_entries,
                allow_head=False,
            ),
            web.post("/did/webvh/witness/log-entries", approve_pending_log_entry),
            web.delete("/did/webvh/witness/log-entries", reject_pending_log_entry),
            web.get(
                "/did/webvh/witness/attested-resources",
                get_pending_attested_resources,
                allow_head=False,
            ),
            web.post(
                "/did/webvh/witness/attested-resources", approve_pending_attested_resource
            ),
            web.delete(
                "/did/webvh/witness/attested-resources", reject_pending_attested_resource
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "did-webvh",
            "description": "Endpoints for managing webvh dids",
            "externalDocs": {
                "description": "Specification",
                "url": "https://www.w3.org/TR/did-core/",
            },
        }
    )
