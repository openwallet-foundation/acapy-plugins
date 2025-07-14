"""Status list entry controller."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.core.error import BaseError
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema
from marshmallow import fields

from .. import status_handler

LOGGER = logging.getLogger(__name__)


class MatchStatusListCredRequest(OpenAPISchema):
    """Match info for request with status list number and entry index."""

    def_id = fields.Str(
        required=True,
        metadata={"description": "Status list definition identifier."},
    )
    cred_id = fields.Str(
        required=False,
        metadata={"description": "Status list credential identifier."},
    )


class StatusListCredSchema(OpenAPISchema):
    """Request schema for querying status list entry."""

    list = fields.Int(
        required=False,
        metadata={"description": "Status list number", "example": 1},
    )
    index = fields.Int(
        required=False,
        metadata={"description": "Status list index", "example": 384},
    )
    status = fields.Str(
        required=False,
        metadata={"description": "Status bitstring", "example": "10"},
    )
    assigned = fields.Bool(
        required=False,
        metadata={"description": "Status assigned", "example": True},
    )


@docs(
    tags=["status-list"],
    summary="Search status list credential by definition and credential identifiers",
)
@match_info_schema(MatchStatusListCredRequest())
@response_schema(StatusListCredSchema(), 200, description="")
@tenant_authentication
async def get_status_list_cred(request: web.BaseRequest):
    """Request handler for querying status list credential by def_id and cred_id."""

    definition_id = request.match_info["def_id"]
    credential_id = request.match_info["cred_id"]

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            result = await status_handler.get_status_list_entry(
                session, definition_id, credential_id
            )
            LOGGER.debug(f"Retrieved status list entry {result}.")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err

    return web.json_response(result)


class UpdateStatusListCredRequest(OpenAPISchema):
    """Request schema for updating status list entry."""

    status = fields.Str(
        required=False,
        default=0,
        metadata={"description": "Status bitstring", "example": "10"},
    )


@docs(
    tags=["status-list"],
    summary="Update status list entry by list number and entry index",
)
@match_info_schema(MatchStatusListCredRequest())
@request_schema(UpdateStatusListCredRequest())
@response_schema(StatusListCredSchema(), 200, description="")
@tenant_authentication
async def update_status_list_cred(request: web.BaseRequest):
    """Request handler for update status list entry by list number and entry index."""

    definition_id = request.match_info["def_id"]
    credential_id = request.match_info["cred_id"]

    body: Dict[str, Any] = await request.json()
    bitstring = body.get("status", None)
    if not bitstring:
        raise web.HTTPBadRequest(reason="status is required")
    if not set(bitstring) <= {"0", "1"}:
        raise web.HTTPBadRequest(reason="status must be valid bitstring of 0 and 1")

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            result = await status_handler.update_status_list_entry(
                session, definition_id, credential_id, bitstring
            )
            LOGGER.debug(f"Updated status list entry {result}.")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err

    return web.json_response(result)


class MatchBindStatusListCredRequest(OpenAPISchema):
    """Request schema for querying status list entry."""

    supported_cred_id = fields.Str(
        required=True,
        metadata={"description": "Status list definition identifier."},
    )
    cred_id = fields.Str(
        required=True,
        metadata={"description": "Status list credential identifier."},
    )


# In cases where credential status binding is NOT automated, we need a way to
# bind a credential to the credential status. This adds additional burden to
# the controller and should be avoided where possible. In cases where it's not
# possible (such as when such a binding does not occur automatically), this
# call can be used to do so manually.
@docs(
    tags=["status-list"],
    summary=(
        "Bind a credential to a status list entry (ideally, this should be automated)"
    ),
)
@match_info_schema(MatchBindStatusListCredRequest())
@response_schema(StatusListCredSchema(), 200, description="")
@tenant_authentication
async def bind_status_list_cred(request: web.BaseRequest):
    """Request handler for update status list entry by list number and entry index."""

    supported_cred_id = request.match_info["supported_cred_id"]
    cred_id = request.match_info["cred_id"]
    result: Dict[str, Any] = {}

    try:
        context: AdminRequestContext = request["context"]
        credential_status = await status_handler.assign_status_entries(
            context, supported_cred_id, cred_id
        )
        if credential_status:
            result["credentialStatus"] = credential_status
        LOGGER.debug(f"Bound status list entry to {cred_id} {result}.")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err

    return web.json_response(result)
