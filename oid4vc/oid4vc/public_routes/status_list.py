"""Status list endpoint for OID4VC."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema
from marshmallow import fields

from ..status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)


class StatusListMatchSchema(OpenAPISchema):
    """Path parameters and validators for status list request."""

    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
        },
    )


@docs(tags=["status-list"], summary="Get status list by list number")
@match_info_schema(StatusListMatchSchema())
async def get_status_list(request: web.Request):
    """Get status list."""

    context: AdminRequestContext = request["context"]
    list_number = request.match_info["list_number"]

    status_handler = context.inject_or(StatusHandler)
    if status_handler:
        status_list = await status_handler.get_status_list(context, list_number)
        return web.Response(text=status_list)
    raise web.HTTPNotFound(reason="Status handler not available")
