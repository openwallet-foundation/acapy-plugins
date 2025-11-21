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

from .config.config import get_global_plugin_config, get_plugin_config, set_config
from .did.controller import ControllerManager
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
    WebvhUpdateSchema,
    WebvhDeactivateSchema,
    WebvhSCIDQueryStringSchema,
    WebvhUpdateWhoisSchema,
)
from .did.witness import WitnessManager
from .protocols.routes import (
    get_pending_witness_requests,
    approve_pending_witness_request,
    reject_pending_witness_request,
)

LOGGER = logging.getLogger(__name__)


@docs(tags=["did-webvh"], summary="Get webvh plugin configuration")
@tenant_authentication
async def get_config(request: web.BaseRequest):
    """Get webvh agent configuration."""
    return web.json_response(await get_plugin_config(request["context"].profile))


@docs(tags=["did-webvh"], summary="Configure webvh plugin")
@request_schema(ConfigureWebvhSchema)
@tenant_authentication
async def configure(request: web.BaseRequest):
    """Configure a webvh agent."""
    profile = request["context"].profile
    request_json = await request.json()

    try:
        options = request_json
        config = await get_plugin_config(profile)
        
        config["server_url"] = options.get(
            "server_url", config.get("server_url")
        ).rstrip( "/")

        if not config.get("server_url"):
            raise OperationError("No server url configured.")
        
        config["scids"] = config.get("scids", {})
        config["witnesses"] = config.get("witnesses", [])
        config["endorsement"] = options.get("endorsement", False)
        config["auto_attest"] = options.get("auto_attest", False)
        config["parameter_options"] = options.get("parameter_options", {})
        config["witness_id"] = options.get("witness_id", config.get("witness_id"))
        
        await set_config(profile, config)
        
        
        config["witness"] = options.get("witness", False)
        if config["witness"]:
            return web.json_response(await WitnessManager(profile).configure(config))
        else:
            return web.json_response(await ControllerManager(profile).configure(config))

    except (ConfigurationError, OperationError) as err:
        return web.json_response({"status": "error", "message": str(err)})




@docs(tags=["did-webvh"], summary="Create a did:webvh")
@request_schema(WebvhCreateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def create(request: web.BaseRequest):
    """Create a Webvh DID."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    manager = ControllerManager(context.profile)
    try:
        log_entry = await manager.create(request_json["options"])
        return web.json_response(await manager.streamline_did_operation(log_entry))
    except (DidCreationError, WitnessError, ConfigurationError) as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Update a did:webvh")
@querystring_schema(WebvhSCIDQueryStringSchema())
@request_schema(WebvhUpdateSchema)
@response_schema(ResolutionResultSchema(), 200)
@tenant_authentication
async def update(request: web.BaseRequest):
    """Update a Webvh log."""
    context: AdminRequestContext = request["context"]
    request_json = await request.json()
    manager = ControllerManager(context.profile)
    try:
        log_entry = await manager.update(
            request.query.get("scid"),
            request_json.get("did_document"),
            request_json.get("options"),
        )
        return web.json_response(await manager.streamline_did_operation(log_entry))
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
    manager = ControllerManager(context.profile)
    try:
        log_entry = await manager.deactivate(
            request.query.get("scid"), request_json.get("options")
        )
        return web.json_response(await manager.streamline_did_operation(log_entry))

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
    manager = ControllerManager(context.profile)

    try:
        did_document = await manager.add_verification_method(
            scid=scid,
            key_type=key_type,
            relationships=relationships,
            key_id=request_json.get("id"),
            multikey=request_json.get("multikey"),
        )
        log_entry = await manager.update(request.query.get("scid"), did_document)
        return web.json_response(await manager.streamline_did_operation(log_entry))
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
    LOGGER.info("Registering WebVH startup event handler")
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the plugin startup setup."""
    LOGGER.info("WebVH startup event received")
    config = get_global_plugin_config(profile)
    LOGGER.info("WebVH global config: %s", config)
    
    if profile.settings.get("multitenant.enabled"):
        LOGGER.info("Skipping WebVH auto_config - multitenant enabled")
        return
    
    if not config.get("auto_config", False):
        LOGGER.info("Skipping WebVH auto_config - auto_config not enabled in config")
        return
    
    LOGGER.info("WebVH auto_config enabled, proceeding with setup")

    # Remove auto_config from config before passing to setup methods
    # so it doesn't get persisted to stored config
    # All other config values (including witness_id) are preserved
    config_without_auto = {k: v for k, v in config.items() if k != "auto_config"}

    if config.get("witness", False):
        await WitnessManager(profile).auto_setup(config_without_auto)
    else:
        await ControllerManager(profile).auto_setup(config_without_auto)
        # Save witness_id to stored config if it's in the global config
        if "witness_id" in config_without_auto:
            stored_config = await get_plugin_config(profile)
            stored_config["witness_id"] = config_without_auto["witness_id"]
            await set_config(profile, stored_config)


async def register(app: web.Application):
    """Register routes for DID Webvh."""
    app.add_routes(
        [
            web.post("/did/webvh/configuration", configure),
            web.get("/did/webvh/configuration", get_config, allow_head=False),
            web.post("/did/webvh/create", create),
            web.post("/did/webvh/update", update),
            web.post("/did/webvh/deactivate", deactivate),
            # web.post(
            #     "/did/webvh/verification-methods",
            #     add_verification_method_request,
            # ),
            # web.delete(
            #     "/did/webvh/verification-methods/{key_id}",
            #     delete_verification_method_request,
            # ),
            web.post("/did/webvh/whois", update_whois),
            web.get(
                "/did/webvh/witness-requests/{record_type}",
                get_pending_witness_requests,
                allow_head=False,
            ),
            web.post(
                "/did/webvh/witness-requests/{record_type}/{record_id}",
                approve_pending_witness_request,
            ),
            web.delete(
                "/did/webvh/witness-requests/{record_type}/{record_id}",
                reject_pending_witness_request,
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
