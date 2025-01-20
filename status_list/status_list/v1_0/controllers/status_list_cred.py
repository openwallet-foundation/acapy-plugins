"""Status list entry controller."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema
from marshmallow import fields
from bitarray import bitarray

from ..models import StatusListDef, StatusListShard, StatusListCred


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
            tag_filter = {
                "definition_id": definition_id,
                "credential_id": credential_id,
            }
            record = await StatusListCred.retrieve_by_tag_filter(session, tag_filter)
            list_number = record.list_number
            entry_index = record.list_index

            definition = await StatusListDef.retrieve_by_id(session, definition_id)
            shard_number = entry_index // definition.shard_size
            shard_index = entry_index % definition.shard_size
            tag_filter = {
                "definition_id": definition_id,
                "list_number": str(list_number),
                "shard_number": str(shard_number),
            }
            shard = await StatusListShard.retrieve_by_tag_filter(session, tag_filter)
            bit_index = shard_index * definition.status_size
            result = {
                "list": definition.list_number,
                "index": entry_index,
                "status": shard.status_bits[
                    bit_index : bit_index + definition.status_size
                ].to01(),
                "assigned": not shard.mask_bits[shard_index],
            }
            LOGGER.debug(f"Retrieved status list entry {result}.")

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

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
    bitstring = body.get("status", 0)

    try:
        if not set(bitstring) <= {"0", "1"}:
            raise ValueError("status must be a bitstring")

        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            tag_filter = {
                "definition_id": definition_id,
                "credential_id": credential_id,
            }
            record = await StatusListCred.retrieve_by_tag_filter(session, tag_filter)
            list_number = record.list_number
            entry_index = record.list_index

            definition = await StatusListDef.retrieve_by_id(session, definition_id)
            shard_number = entry_index // definition.shard_size
            shard_index = entry_index % definition.shard_size
            tag_filter = {
                "definition_id": definition_id,
                "list_number": str(list_number),
                "shard_number": str(shard_number),
            }
            shard = await StatusListShard.retrieve_by_tag_filter(
                session, tag_filter, for_update=True
            )
            bit_index = shard_index * definition.status_size
            status_bits = shard.status_bits
            status_bits[bit_index : bit_index + definition.status_size] = bitarray(
                bitstring
            )
            shard.status_bits = status_bits
            await shard.save(session, reason="Update status list entry.")

            result = {
                "list": definition.list_number,
                "index": entry_index,
                "status": shard.status_bits[
                    bit_index : bit_index + definition.status_size
                ].to01(),
                "assigned": not shard.mask_bits[shard_index],
            }
            LOGGER.debug(f"Updated status list entry {result}.")

    except (ValueError, BaseModelError, StorageError, StorageNotFoundError) as err:
        reason = getattr(err, "roll_up", None) or str(err)
        raise web.HTTPBadRequest(reason=reason) from err

    return web.json_response(result)
