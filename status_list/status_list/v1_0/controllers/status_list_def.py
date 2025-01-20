"""Status list definition controller."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
    match_info_schema,
    querystring_schema,
)
from marshmallow import fields
from marshmallow.validate import OneOf

from ..models import StatusListDef, StatusListDefSchema, StatusListShard
from .. import status_handler

LOGGER = logging.getLogger(__name__)


class CreateStatusListDefRequest(OpenAPISchema):
    """Request schema for creating status list definition."""

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Supported credential identifier"},
    )
    status_purpose = fields.Str(
        required=False,
        default="revocation",
        metadata={
            "description": "Status purpose: revocation, suspension or message",
            "example": "revocation",
        },
    )
    status_message = fields.Dict(
        required=False,
        default=None,
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
        default=1,
        metadata={"description": "Status size in bits", "example": 1},
    )
    shard_size = fields.Int(
        required=False,
        metadata={
            "description": "Number of entries in each shard, between 1 and list_size",
            "example": 1024,
        },
    )
    list_size = fields.Int(
        required=False,
        metadata={
            "description": "Number of entries in status list, minimum 131072",
            "example": 131072,
        },
    )


class CreateStatusListDefResponse(OpenAPISchema):
    """Response schema for creating status list definition."""

    status = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    id = fields.Str(
        required=True, metadata={"description": "status list definition id."}
    )


@docs(
    tags=["status-list"],
    summary="Create a new status list definition",
)
@request_schema(CreateStatusListDefRequest())
@response_schema(StatusListDefSchema(), 200, description="")
@tenant_authentication
async def create_status_list_def(request: web.BaseRequest):
    """Request handler for creating a status list definition."""

    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"Creating status list definition with: {body}")

    supported_cred_id = body.get("supported_cred_id", None)

    status_purpose = body.get("status_purpose", None)
    if status_purpose is None:
        raise ValueError("status_purpose is required.")

    status_size = body.get("status_size", None)
    if status_size is None:
        raise ValueError("status_size is required.")

    if status_size > 1:
        status_message = body.get("status_message", None)
        if status_message is None:
            raise ValueError("status_message is required.")
    else:
        status_message = None

    if status_purpose == "message" and status_message is None:
        raise ValueError("status_message is required.")

    shard_size = body.get("shard_size", None)

    list_size = body.get("list_size", None)

    definition = StatusListDef(
        supported_cred_id=supported_cred_id,
        status_purpose=status_purpose,
        status_message=status_message,
        status_size=status_size,
        shard_size=shard_size,
        list_size=list_size,
    )

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.transaction() as txn:
            # Create status list definition
            await definition.save(txn, reason="Save status list definition.")

            # Create current status list
            definition.list_number = definition.next_list_number = 0
            definition.list_index = 0
            await status_handler.create_next_status_list(txn, definition)

            # Create next status list
            definition.next_list_number = 1
            await status_handler.create_next_status_list(txn, definition)

            # Update status list definition list numbers
            await definition.save(txn, reason="Save status list definition.")

            # Commit all changes
            await txn.commit()

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    LOGGER.debug(f"Created status list definition: {definition}")

    return web.json_response(definition.serialize())


class QueryStatusListDefRequest(OpenAPISchema):
    """Request schema for querying status list definition."""

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Supported credential identifier"},
    )
    status_purpose = fields.Str(
        required=False,
        validate=OneOf(["revocation", "suspension", "message"]),
        metadata={"description": "Filter by status purpose."},
    )


class QueryStatusListDefResponse(OpenAPISchema):
    """Response schema for querying status list definition."""

    results = fields.Nested(
        StatusListDefSchema(),
        many=True,
        metadata={"description": "Status list definitions."},
    )


@docs(
    tags=["status-list"],
    summary="Search status list definitions by filters.",
)
@querystring_schema(QueryStatusListDefRequest())
@response_schema(QueryStatusListDefResponse(), 200, description="")
@tenant_authentication
async def get_status_list_defs(request: web.BaseRequest):
    """Request handler for querying status list definitions."""

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            tag_filter = {
                attr: value
                for attr in (
                    "supported_cred_id",
                    "status_purpose",
                )
                if (value := request.query.get(attr))
            }
            records = await StatusListDef.query(session=session, tag_filter=tag_filter)
            results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)


class MatchStatusListDefRequest(OpenAPISchema):
    """Match info for request with id."""

    def_id = fields.Str(
        required=True,
        metadata={"description": "status list definition identifier."},
    )


@docs(
    tags=["status-list"],
    summary="Search status list definition by identifier",
)
@match_info_schema(MatchStatusListDefRequest())
@response_schema(StatusListDefSchema(), 200, description="")
@tenant_authentication
async def get_status_list_def(request: web.BaseRequest):
    """Request handler for querying status list definition by identifier."""

    id = request.match_info["def_id"]

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            record = await StatusListDef.retrieve_by_id(session, id)
            result = record.serialize()

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class DeleteStatusListDefRequest(OpenAPISchema):
    """Delete status list definition request."""

    recursive_delete = fields.Bool(
        required=True,
        metadata={
            "description": "Delete all underlying status list and entries recursively",
            "example": False,
        },
    )


class DeleteStatusListDefResponse(OpenAPISchema):
    """Delete status list definition response."""

    deleted = fields.Str(required=True)
    id = fields.Str(required=False)
    error = fields.Str(required=False)


@docs(
    tags=["status-list"],
    summary="Delete a status list definition by identifier",
)
@match_info_schema(MatchStatusListDefRequest())
@request_schema(DeleteStatusListDefRequest())
@response_schema(DeleteStatusListDefResponse(), 200, description="")
@tenant_authentication
async def delete_status_list_def(request: web.Request):
    """Request handler for deleting a status list definition."""

    definition_id = request.match_info["def_id"]
    body: Dict[str, Any] = await request.json()
    recursive_delete = body.get("recursive_delete", False)

    if recursive_delete:
        try:
            context: AdminRequestContext = request["context"]
            async with context.profile.transaction() as txn:
                # delete status list shards
                shards = await StatusListShard.query(
                    txn, {"definition_id": definition_id}
                )
                for shard in shards:
                    await shard.delete_record(txn)

                # delete status list definition
                definition = await StatusListDef.retrieve_by_id(txn, definition_id)
                await definition.delete_record(txn)

                # commit all changes
                await txn.commit()

                # create response
                result = {"deleted": True, "def_id": definition_id}

        except (StorageError, StorageNotFoundError, BaseModelError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
    else:
        result = {
            "deleted": False,
            "error": "Please set recursive_delete to true to delete the status definition and all underlying status lists.",
        }

    return web.json_response(result)
