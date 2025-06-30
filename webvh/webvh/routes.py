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

from .config.config import get_plugin_config, set_config
from .did.manager import ControllerManager
from .did.exceptions import (
    ConfigurationError,
    DidCreationError,
    DidUpdateError,
    OperationError,
)
from .did.models.operations import (
    ConfigureWebvhSchema,
    WebvhAddVMSchema,
    WebvhCreateSchema,
    WebvhCreateWitnessInvitationSchema,
    WebvhDeactivateSchema,
    WebvhDIDQueryStringSchema,
    WebvhSCIDQueryStringSchema,
    WebvhUpdateWhoisSchema,
)
from .did.utils import decode_invitation
from .witness.manager import WitnessManager
from .witness.exceptions import WitnessError

LOGGER = logging.getLogger(__name__)


@docs(tags=["did-webvh"], summary="Get webvh agent configuration")
@tenant_authentication
async def get_config(request: web.BaseRequest):
    """Get webvh agent configuration."""
    return web.json_response(
        await get_plugin_config(request["context"].profile)
    )


@docs(tags=["did-webvh"], summary="Configure a webvh agent")
@request_schema(ConfigureWebvhSchema)
@tenant_authentication
async def configure(request: web.BaseRequest):
    """Configure a webvh agent."""
    profile = request["context"].profile
    request_json = await request.json()

    # Build the config object
    config = await get_plugin_config(profile)
    if not config.get("server_url"):
        raise ConfigurationError("No server url configured.")

    config["scids"] = config.get("scids", {})
    config["witnesses"] = config.get("witnesses", [])
    config["server_url"] = request_json.get(
        "server_url", config.get("server_url")
    ).rstrip("/")
    config["endorsement"] = request_json.get("endorsement", False)
    
    await set_config(profile, config)

    try:
        if request_json.get("witness"):
            return web.json_response(
                await WitnessManager(profile).configure(
                    request_json.get("auto_attest", False),
                    request_json.get("witness_key", None)
                )
            )

        elif not request_json.get("witness"):
            return web.json_response(
                await ControllerManager(profile).configure(
                    witness_invitation=request_json.get("witness_invitation", None)
                )
            )

    except (ConfigurationError, OperationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Create a witness invitation")
@request_schema(WebvhCreateWitnessInvitationSchema)
@tenant_authentication
async def witness_create_invite(request: web.BaseRequest):
    """Create a witness invitation."""
    context: AdminRequestContext = request["context"]
    body = await request.json() if request.body_exists else {}
    profile = context.profile
    try:
        return web.json_response(
            await WitnessManager(profile).create_invitation(
                body.get("alias"), body.get("label"), body.get("multi")
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


@docs(tags=["did-webvh"], summary="Get all pending log entries")
@tenant_authentication
async def get_pending_log_entries(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]
    pending_log_entries = await WitnessManager(
        context.profile
    ).get_pending_log_entries()
    return web.json_response({"results": pending_log_entries})


@docs(tags=["did-webvh"], summary="Approve a pending log entry")
@querystring_schema(WebvhSCIDQueryStringSchema())
@tenant_authentication
async def approve_pending_log_entry(request: web.BaseRequest):
    """Approve a pending log entry."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await WitnessManager(context.profile).approve_log_entry(
                request.query.get("scid"))
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject a pending log entry")
@querystring_schema(WebvhSCIDQueryStringSchema())
@tenant_authentication
async def reject_pending_log_entry(request: web.BaseRequest):
    """Reject a pending log entry."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await WitnessManager(context.profile).reject_log_entry(
                request.query.get("scid"))
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Get all pending attested resources")
@tenant_authentication
async def get_pending_attested_resources(request: web.BaseRequest):
    """Get all pending attested resources."""
    context: AdminRequestContext = request["context"]
    pending_log_entries = await WitnessManager(
        context.profile
    ).get_pending_attested_resources()
    return web.json_response({"results": pending_log_entries})


@docs(tags=["did-webvh"], summary="Approve a pending attested resource")
@querystring_schema(WebvhSCIDQueryStringSchema())
@tenant_authentication
async def approve_pending_attested_resource(request: web.BaseRequest):
    """Approve a pending attested resource."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await WitnessManager(context.profile).approve_attested_resource(
                request.query.get("scid"))
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject a pending attested resource")
@querystring_schema(WebvhSCIDQueryStringSchema())
@tenant_authentication
async def reject_pending_attested_resource(request: web.BaseRequest):
    """Reject a pending attested resource."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await WitnessManager(context.profile).reject_attested_resource(
                request.query.get("scid"))
        )
    except WitnessError as err:
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


# def register_events(event_bus: EventBus):
#     """Register to the acapy startup event."""
#     event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


# async def on_startup_event(profile: Profile, event: Event):
#     """Handle the witness setup."""
#     if not profile.settings.get("multitenant.enabled"):
#         await ControllerManager(profile).auto_witness_setup()


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes([
        web.post("/did/webvh/configuration", configure),
        web.get("/did/webvh/configuration", get_config, allow_head=False),
        web.post("/did/webvh/controller/create", create),
        web.post("/did/webvh/controller/update", update),
        web.post("/did/webvh/controller/deactivate", deactivate),
        web.post("/did/webvh/controller/verification-methods", 
                 add_verification_method_request),
        web.delete("/did/webvh/controller/verification-methods/{key_id}",
                delete_verification_method_request),
        web.post("/did/webvh/controller/whois", update_whois),
        web.post("/did/webvh/witness/invitations", witness_create_invite),
        web.get("/did/webvh/witness/log-entries", 
                get_pending_log_entries, allow_head=False),
        web.post("/did/webvh/witness/log-entries", approve_pending_log_entry),
        web.delete("/did/webvh/witness/log-entries", reject_pending_log_entry),
        web.get("/did/webvh/witness/attested-resources", 
                get_pending_attested_resources, allow_head=False),
        web.post("/did/webvh/witness/attested-resources", 
                 approve_pending_attested_resource),
        web.delete("/did/webvh/witness/attested-resources", 
                   reject_pending_attested_resource)
    ])


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
