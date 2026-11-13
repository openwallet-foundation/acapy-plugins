"""Status list endpoint for OID4VC."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.jwt import b64_to_dict
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema
from marshmallow import fields
from werkzeug.datastructures import MIMEAccept
from werkzeug.http import parse_accept_header

from ..status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)

STATUSLIST_JWT = "application/statuslist+jwt"
STATUSLIST_CWT = "application/statuslist+cwt"


class StatusListMatchSchema(OpenAPISchema):
    """Path parameters and validators for status list request."""

    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
        },
    )


def _jwt_typ(token: str):
    """The JWT `typ` header, if the token is a JWT."""
    try:
        return b64_to_dict(token.split(".")[0]).get("typ")
    except ValueError:
        return None


@docs(tags=["status-list"], summary="Get status list by list number")
@match_info_schema(StatusListMatchSchema())
async def get_status_list(request: web.Request):
    """Get status list."""

    context: AdminRequestContext = request["context"]
    list_number = request.match_info["list_number"]

    status_handler = context.inject_or(StatusHandler)
    if status_handler:
        accept = ", ".join(request.headers.getall("Accept", [])) or None
        accepted_type = parse_accept_header(accept, MIMEAccept).best_match(
            [STATUSLIST_JWT, STATUSLIST_CWT]
        )
        status_list = await status_handler.get_status_list(
            context,
            list_number,
            token_format="cwt" if accepted_type == STATUSLIST_CWT else "jwt",
        )
        if status_list is None:
            raise web.HTTPNotFound(reason="Status handler not available")
        if isinstance(status_list, bytes):
            return web.Response(
                body=status_list,
                content_type=STATUSLIST_CWT,
                headers={"Vary": "Accept"},
            )
        if _jwt_typ(status_list) == "statuslist+jwt":
            return web.Response(
                body=status_list.encode(),
                content_type=STATUSLIST_JWT,
                headers={"Vary": "Accept"},
            )
        return web.Response(text=status_list)
    raise web.HTTPNotFound(reason="Status handler not available")
