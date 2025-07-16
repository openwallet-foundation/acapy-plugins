"""DID Webvh protocol routes module."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema
from ...did.models.operations import (
    WebvhSCIDQueryStringSchema
)
from ...did.witness import WitnessManager
from ...did.exceptions import WitnessError


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
                request.query.get("scid")
            )
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
                request.query.get("scid")
            )
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})
