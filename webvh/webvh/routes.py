"""DID Webvh routes module."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN
from acapy_agent.resolver.routes import ResolutionResultSchema
import re
from acapy_agent.wallet.keys.manager import MultikeyManagerError
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, request_schema, response_schema

from .config.config import (
    get_global_plugin_config,
    get_plugin_config,
    get_server_url,
    set_config,
)
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
from .did.utils import format_witness_ready_message
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

        if not (server_url := options.get("server_url", config.get("server_url", None))):
            raise OperationError("No server url configured.")

        config["witness"] = options.get("witness", False)
        config["witness_id"] = options.get("witness_id", config.get("witness_id"))
        config["server_url"] = server_url.rstrip("/")

        config["scids"] = config.get("scids", {})
        config["witnesses"] = config.get("witnesses", [])
        config["endorsement"] = options.get("endorsement", False)
        config["auto_attest"] = options.get("auto_attest", False)

        config["parameter_options"] = options.get("parameter_options", {})

        await set_config(profile, config)

        if config["witness"]:
            manager = WitnessManager(profile)
        else:
            manager = ControllerManager(profile)
        return web.json_response(await manager.configure(config))

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
    msg = "Registering WebVH startup event handler"
    LOGGER.info("=" * 70)
    LOGGER.info(msg)
    LOGGER.info("=" * 70)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup_event)
    msg2 = "WebVH startup event handler registered successfully"
    LOGGER.info(msg2)

    # Subscribe to subwallet creation events
    SUBWALLET_CREATED_PATTERN = re.compile("^acapy::multitenant::wallet::created::.*$")
    event_bus.subscribe(SUBWALLET_CREATED_PATTERN, on_subwallet_created_event)
    msg3 = "WebVH subwallet creation event handler registered successfully"
    LOGGER.info(msg3)


async def on_startup_event(profile: Profile, event: Event):
    """Handle the plugin startup setup."""

    config = get_global_plugin_config(profile)

    # Skip if multitenant enabled or auto_config disabled
    if profile.settings.get("multitenant.enabled"):
        return

    if not config.pop("auto_config", False):
        return

    if config.get("witness", False):
        # Configure witness and print information
        LOGGER.info("Configuring witness service...")
        witness_config = await WitnessManager(profile).configure(config)
        # Get server_url from config or profile
        try:
            server_url = await get_server_url(profile)
        except ConfigurationError:
            server_url = None
        message = format_witness_ready_message(
            witness_config["witness_id"],
            witness_config.get("invitation_url"),
            server_url=server_url,
        )
        # Log the entire banner as a single message
        LOGGER.info(f"\n{message}")
    else:
        # Configure controller (sets up witness connection if witness_id is configured)
        await ControllerManager(profile).configure(config)


async def on_subwallet_created_event(profile: Profile, event: Event):
    """Handle subwallet creation event in multitenant mode.

    This handler logs when a new subwallet is created but doesn't perform
    any setup actions - subwallets need to be configured separately.
    """
    wallet_id = event.payload.get("wallet_id") if event.payload else None
    wallet_name = event.payload.get("wallet_name") if event.payload else None

    msg = f"Subwallet created - wallet_id: {wallet_id}, wallet_name: {wallet_name}"
    LOGGER.info(msg)

    if wallet_id:
        msg2 = (
            f"Subwallet {wallet_id} created. "
            "Configure WebVH settings via /did/webvh/configuration endpoint."
        )
        LOGGER.info(msg2)


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
