"""Status list definition controller."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.error import BaseError
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

from ..error import StatusListError
from ..models import StatusListDef, StatusListDefSchema, StatusListShard, StatusListCred
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
    status_message = fields.List(
        fields.Dict(),
        required=False,
        default=None,
        metadata={
            "description": "Status List message status",
            "example": [
                {"status": "0x00", "message": "active"},
                {"status": "0x01", "message": "revoked"},
                {"status": "0x10", "message": "pending"},
                {"status": "0x11", "message": "suspended"},
            ],
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
    list_type = fields.Str(
        required=False,
        metadata={
            "description": "Status list type: 'w3c', 'ietf' or none",
            "example": "ietf",
        },
    )
    issuer_did = fields.Str(
        required=False,
        metadata={
            "description": "Issuer DID for the status list",
            "example": "did:web:dev.lab.di.gov.on.ca",
        },
    )
    verification_method = fields.Str(
        required=False,
        metadata={
            "description": "Issuer DID for the status list",
            "example": (
                "did:web:dev.lab.di.gov.on.ca#"
                "z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )


class CreateStatusListDefResponse(OpenAPISchema):
    """Response schema for creating status list definition."""

    status = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    id = fields.Str(required=True, metadata={"description": "status list definition id."})


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

    list_size = body.get("list_size", None)
    if list_size and (list_size <= 0 or (list_size & (list_size - 1)) != 0):
        raise web.HTTPBadRequest(reason="list_size must be a power of two.")

    shard_size = body.get("shard_size", None)
    if shard_size and shard_size <= 0:
        raise web.HTTPBadRequest(reason="shard size is not valid.")

    status_size = body.get("status_size", None)
    if status_size and status_size <= 0:
        raise web.HTTPBadRequest(reason="status size is not valid.")

    status_purpose = body.get("status_purpose", None)
    if status_purpose == "message":
        status_message = body.get("status_message", None)
        if status_message is None:
            raise web.HTTPBadRequest(reason="statis message definition is required.")
    elif status_size and status_size > 1:
        raise web.HTTPBadRequest(reason="status size is not valid.")
    else:
        status_message = None

    supported_cred_id = body.get("supported_cred_id", None)

    list_type = body.get("list_type", None)
    issuer_did = body.get("issuer_did", None)
    verification_method = body.get("verification_method", None)

    try:
        context: AdminRequestContext = request["context"]
        wallet_id = status_handler.get_wallet_id(context)

        async with context.profile.transaction() as txn:
            # Create status list definition
            definition = StatusListDef(
                supported_cred_id=supported_cred_id,
                status_purpose=status_purpose,
                status_message=status_message,
                status_size=status_size,
                shard_size=shard_size,
                list_size=list_size,
                list_type=list_type,
                issuer_did=issuer_did,
                verification_method=verification_method,
            )
            # Create current status list
            list_number = await status_handler.assign_status_list_number(txn, wallet_id)
            definition.next_list_number = definition.list_number = list_number
            definition.add_list_number(list_number)
            await definition.save(txn, reason="Save status list definition.")
            await status_handler.create_next_status_list(txn, definition)

            # Create spare status list
            list_number = await status_handler.assign_status_list_number(txn, wallet_id)
            definition.next_list_number = list_number
            definition.add_list_number(list_number)
            await status_handler.create_next_status_list(txn, definition)

            # Update status list definition list numbers
            await definition.save(txn, reason="Save status list definition.")

            # Commit all changes
            await txn.commit()

            # Return created status list definition
            LOGGER.debug(f"Created status list definition: {definition}")
            return web.json_response(definition.serialize())

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StatusListError, StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err


class QueryStatusListDefRequest(OpenAPISchema):
    """Request schema for querying status list definition."""

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Supported credential identifier"},
    )
    status_purpose = fields.Str(
        required=False,
        validate=OneOf(["refresh", "revocation", "suspension", "message"]),
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

            return web.json_response(results)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err


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

        return web.json_response(result)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err


class DeleteStatusListDefRequest(OpenAPISchema):
    """Delete status list definition request."""

    recursive_delete = fields.Bool(
        required=True,
        metadata={
            "description": "Delete all underlying status list and entries recursively",
            "example": False,
        },
    )


class UpdateStatusListDefRequest(OpenAPISchema):
    """Request schema for updating status list definition."""

    list_type = fields.Str(
        required=False,
        metadata={
            "description": "Status list type: 'w3c', 'ietf' or none",
            "example": "ietf",
        },
    )
    issuer_did = fields.Str(
        required=False,
        metadata={
            "description": "Issuer DID for the status list",
            "example": "did:web:dev.lab.di.gov.on.ca",
        },
    )
    verification_method = fields.Str(
        required=False,
        metadata={
            "description": "Issuer DID for the status list",
            "example": (
                "did:web:dev.lab.di.gov.on.ca#"
                "z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )


@docs(
    tags=["status-list"],
    summary="Update status list definition by identifier",
)
@match_info_schema(MatchStatusListDefRequest())
@request_schema(UpdateStatusListDefRequest())
@response_schema(StatusListDefSchema(), 200, description="")
@tenant_authentication
async def update_status_list_def(request: web.BaseRequest):
    """Request handler for update status list definition by identifier."""

    definition_id = request.match_info["def_id"]
    body: Dict[str, Any] = await request.json()

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.transaction() as txn:
            definition = await StatusListDef.retrieve_by_id(
                txn, definition_id, for_update=True
            )
            definition.list_type = body.get("list_type", None)
            definition.issuer_did = body.get("issuer_did", None)
            definition.verification_method = body.get("verification_method", None)

            # Save updated status list definition
            await definition.save(txn, reason="Update status list definition.")

            # Commit all changes
            await txn.commit()

            LOGGER.debug(f"Updated status list definition: {definition}.")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err

    return web.json_response(definition.serialize())


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
                # detete status list creds
                creds = await StatusListCred.query(txn, {"definition_id": definition_id})
                for cred in creds:
                    await cred.delete_record(txn)

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

        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err

        except (StorageError, BaseModelError, BaseError) as err:
            raise web.HTTPInternalServerError(reason=err.roll_up) from err

    else:
        result = {
            "deleted": False,
            "error": (
                "Please set recursive_delete to true to delete the status definition "
                "and all underlying status lists, entries and credentials."
            ),
        }

    return web.json_response(result)
