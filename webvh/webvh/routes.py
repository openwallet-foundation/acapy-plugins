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
from .did.controller_manager import ControllerManager
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
    WebvhDIDQueryStringSchema,
    WebvhSCIDQueryStringSchema,
    WebvhUpdateWhoisSchema,
)
from .did.utils import decode_invitation
from .did.witness_manager import WitnessManager

LOGGER = logging.getLogger(__name__)


@docs(tags=["did-webvh"], summary="Get webvh agent configuration")
@tenant_authentication
async def get_config(request: web.BaseRequest):
    """Get webvh agent configuration."""
    profile = request["context"].profile
    config = await get_plugin_config(profile)
    return web.json_response(config)


@docs(tags=["did-webvh"], summary="Configure a webvh agent")
@request_schema(ConfigureWebvhSchema)
@tenant_authentication
async def configure(request: web.BaseRequest):
    """Configure a webvh agent."""
    profile = request["context"].profile
    request_json = await request.json()

    # Build the config object
    config = await get_plugin_config(profile)

    config["scids"] = config.get("scids") or {}
    config["witnesses"] = config.get("witnesses") or []
    config["server_url"] = (
        request_json.get("server_url") or config.get("server_url")
    ).rstrip("/")

    if not config.get("server_url"):
        raise ConfigurationError("No server url provided.")

    try:
        witness_manager = WitnessManager(profile)
        if request_json.get("witness"):
            config["role"] = "witness"
            config["auto_attest"] = request_json.get("auto_attest")
            witness_key_info = await witness_manager.setup_witness_key(
                config["server_url"], request_json.get("witness_key")
            )
            witness_key = witness_key_info.get("multikey")
            if not witness_key:
                raise ConfigurationError("No witness key set.")

            if f"did:key:{witness_key}" not in config["witnesses"]:
                config["witnesses"].append(f"did:key:{witness_key}")

            await set_config(profile, config)

            return web.json_response(witness_key_info)

        elif not request_json.get("witness"):
            config["role"] = "controller"
            config["witness_invitation"] = request_json.get("witness_invitation")

            if not config.get("witness_invitation"):
                raise ConfigurationError("No witness invitation provided.")

            try:
                witness_invitation = decode_invitation(config["witness_invitation"])
            except UnicodeDecodeError:
                raise ConfigurationError("Invalid witness invitation.")

            if (
                not witness_invitation.get("goal").startswith("did:key:")
                and not witness_invitation.get("goal-code") == "witness-service"
            ):
                raise ConfigurationError("Missing invitation goal-code and witness did.")

            if witness_invitation.get("goal") not in config["witnesses"]:
                config["witnesses"].append(witness_invitation.get("goal"))

            await set_config(profile, config)

            await witness_manager.auto_witness_setup()

            return web.json_response({"status": "success"})

    except ConfigurationError as err:
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
                body.get("alias"), body.get("label")
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
            await ControllerManager(context.profile).register(
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


@docs(tags=["did-webvh"], summary="Get all pending registration requests")
@tenant_authentication
async def get_pending_registrations(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]
    pending_requests = await WitnessManager(
        context.profile
    ).get_pending_did_request_docs()
    return web.json_response({"results": pending_requests})


@docs(tags=["did-webvh"], summary="Approve a pending registration")
@querystring_schema(WebvhDIDQueryStringSchema())
@tenant_authentication
async def approve_pending_registration(request: web.BaseRequest):
    """Approve a pending registration."""
    context: AdminRequestContext = request["context"]

    try:
        controller_id = request.query.get("did")
        return web.json_response(
            await WitnessManager(context.profile).attest_did_request_doc(controller_id)
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject a pending registration")
@querystring_schema(WebvhDIDQueryStringSchema())
@tenant_authentication
async def reject_pending_registration(request: web.BaseRequest):
    """Reject a pending registration."""
    context: AdminRequestContext = request["context"]

    try:
        controller_id = request.query.get("did")
        return web.json_response(
            await WitnessManager(context.profile).reject_did_request_doc(controller_id)
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


def register_events(event_bus: EventBus):
    """Register to the acapy startup event."""
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the witness setup."""
    if not profile.settings.get("multitenant.enabled"):
        await WitnessManager(profile).auto_witness_setup()


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes([web.post("/did/webvh/configuration", configure)])
    app.add_routes([web.get("/did/webvh/configuration", get_config, allow_head=False)])
    # app.add_routes(
    #     [web.get("/did/webvh/controller/parameters", get_scid_info, allow_head=False)]
    # )
    app.add_routes([web.post("/did/webvh/controller/create", create)])
    app.add_routes([web.post("/did/webvh/controller/update", update)])
    app.add_routes([web.post("/did/webvh/controller/deactivate", deactivate)])
    app.add_routes(
        [
            web.post(
                "/did/webvh/controller/verification-methods",
                add_verification_method_request,
            )
        ]
    )
    app.add_routes(
        [
            web.delete(
                "/did/webvh/controller/verification-methods/{key_id}",
                delete_verification_method_request,
            )
        ]
    )
    app.add_routes(
        [
            web.post(
                "/did/webvh/controller/whois",
                update_whois,
            )
        ]
    )
    app.add_routes([web.post("/did/webvh/witness/invitations", witness_create_invite)])
    app.add_routes(
        [
            web.get(
                "/did/webvh/witness/registrations",
                get_pending_registrations,
                allow_head=False,
            )
        ]
    )
    app.add_routes(
        [
            web.post(
                "/did/webvh/witness/registrations",
                approve_pending_registration,
            )
        ]
    )
    app.add_routes(
        [
            web.delete(
                "/did/webvh/witness/registrations",
                reject_pending_registration,
            )
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
