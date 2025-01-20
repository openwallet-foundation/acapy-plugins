"""Status list entry controller."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, response_schema, match_info_schema
from marshmallow import fields

from .. import status_handler


LOGGER = logging.getLogger(__name__)


class MatchStatusListDefRequest(OpenAPISchema):
    """Match info for request with identifier."""

    def_id = fields.Str(
        required=True,
        metadata={"description": "Filter by status list definition identifier."},
    )


class AssignStatusListEntryResponse(OpenAPISchema):
    """Response schema for creating status list entry."""

    status_list_id = fields.Str(
        required=False,
        metadata={
            "description": "Status list identifier",
        },
    )
    index = fields.Int(
        required=False,
        metadata={"description": "Status index", "example": 3},
    )
    status = fields.Str(
        required=False,
        metadata={"description": "Status bitstring", "example": "10"},
    )


@docs(
    tags=["status-list"],
    summary="Assign a status list entry",
)
@match_info_schema(MatchStatusListDefRequest())
@response_schema(AssignStatusListEntryResponse(), 200, description="")
@tenant_authentication
async def assign_status_list_entry(request: web.BaseRequest):
    """Request handler for assigning a status list entry."""

    definition_id = request.match_info["def_id"]

    try:
        context: AdminRequestContext = request["context"]
        result = await status_handler.assign_status_list_entry(context, definition_id)

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)
