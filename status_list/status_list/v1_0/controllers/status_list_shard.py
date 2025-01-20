"""Status list controller."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, response_schema, match_info_schema, querystring_schema
from marshmallow import fields
from marshmallow.validate import OneOf

from ..models import StatusListDef
from .. import status_handler

LOGGER = logging.getLogger(__name__)


class MatchStatusListRequest(OpenAPISchema):
    """Match info for request with identifier."""

    def_id = fields.Str(
        required=True,
        metadata={"description": "Status list definition identifier."},
    )
    list_num = fields.Str(
        required=False,
        metadata={"description": "Status list number."},
    )


class QueryStatusListRequest(OpenAPISchema):
    """Request schema for querying status list."""

    status_type = fields.Str(
        required=False,
        validate=OneOf(["w3c", "ietf"]),
        metadata={"description": "Status list format.", "example": "w3c"},
    )
    issuer_did = fields.Str(
        required=False,
        metadata={
            "description": "Issuer did",
            "example": "did:web:issuer",
        },
    )


class StatusListSchema(OpenAPISchema):
    """Status List Schema."""

    definition_id = fields.Str(
        required=False,
        metadata={"description": "Status list definition identifier"},
    )
    list_number = fields.Str(
        required=False,
        metadata={"description": "Status list number."},
    )
    list_size = fields.Int(
        required=False,
        metadata={
            "description": "Number of entries in status list, minimum 131072",
            "example": 131072,
        },
    )
    status_purpose = fields.Str(
        required=False,
        validate=OneOf(["revocation", "suspension", "message"]),
        metadata={
            "description": "Status purpose.",
            "example": "revocation",
        },
    )
    status_message = fields.Dict(
        required=False,
        metadata={
            "description": "Status List message status",
            "example": {
                "0x00": "active",
                "0x01": "revoked",
                "0x10": "pending",
                "0x11": "suspended",
            },
        },
    )
    status_size = fields.Int(
        required=False,
        metadata={"description": "Status size in bits", "example": 1},
    )
    encoded_list = fields.Str(
        required=False,
        metadata={"description": "GZIP compressed and base64url encoded status list"},
    )


@docs(
    tags=["status-list"],
    summary="Search status list by list number",
)
@match_info_schema(MatchStatusListRequest())
@querystring_schema(QueryStatusListRequest())
@response_schema(StatusListSchema(), 200, description="")
@tenant_authentication
async def get_status_list(request: web.BaseRequest):
    """Request handler for querying status list by list number."""

    definition_id = request.match_info["def_id"]
    list_number = request.match_info["list_num"]
    status_type = request.query.get("status_type")
    issuer_did = request.query.get("issuer_did", "did:web:issuer")

    try:
        context: AdminRequestContext = request["context"]

        async with context.profile.session() as session:
            definition = await StatusListDef.retrieve_by_id(session, definition_id)

        result = await status_handler.get_status_list(
            context, definition, list_number, status_type, issuer_did
        )

    except Exception as err:
        reason = getattr(err, "roll_up", None) or str(err)
        raise web.HTTPBadRequest(reason=reason) from err

    return web.json_response(result)
