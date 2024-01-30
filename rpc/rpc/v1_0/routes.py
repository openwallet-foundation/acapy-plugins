"""Routes for DIDComm RPC v1.0."""

import json
import logging

from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields, validate

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.connections.models.conn_record import ConnRecord
from aries_cloudagent.messaging.models.base import (
    BaseModel,
    BaseModelSchema,
    BaseModelError,
)
from aries_cloudagent.messaging.models.base_record import match_post_filter
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import UUID4_EXAMPLE
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError

from rpc.v1_0.models import (
    RPC_REQUEST_EXAMPLE,
    RPC_RESPONSE_EXAMPLE,
    DRPCRecord,
    DRPCRecordSchema,
    Request,
    Response,
)
from rpc.v1_0.messages import (
    DRPCRequestMessage,
    DRPCRequestMessageSchema,
    DRPCResponseMessage,
    DRPCResponseMessageSchema,
)

LOGGER = logging.getLogger(__name__)


class DRPCRequest(BaseModel):
    """DIDComm RPC Request Model."""

    class Meta:
        """DRPCRequest metadata."""

        schema_class = "DRPCRequestSchema"

    def __init__(self, *, connection_id: str = None, request: dict = None, **kwargs):
        """Initialize DIDComm RPC Request Model."""

        super().__init__(**kwargs)
        self.connection_id = connection_id
        self.request = request


class DRPCResponse(BaseModel):
    """DIDComm RPC Response Model."""

    class Meta:
        """DRPCResponse metadata."""

        schema_class = "DRPCResponseSchema"

    def __init__(
        self,
        *,
        connection_id: str = None,
        response: dict = None,
        thread_id: str = None,
        **kwargs,
    ):
        """Initialize DIDComm RPC Response Model."""

        super().__init__(**kwargs)
        self.connection_id = connection_id
        self.response = response
        self.thread_id = thread_id


class DRPCRequestSchema(BaseModelSchema, OpenAPISchema):
    """Request schema for sending a DIDComm RPC Request."""

    class Meta:
        """DRPCRequestSchema metadata."""

        model_class = "DRPCRequest"

    connection_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    request = Request(
        required=True,
        metadata={"description": "RPC Request", "example": RPC_REQUEST_EXAMPLE},
    )


class DRPCResponseSchema(BaseModelSchema, OpenAPISchema):
    """Request schema for sending a DIDComm RPC Response."""

    class Meta:
        """DRPCResponseSchema metadata."""

        model_class = "DRPCResponse"

    connection_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    response = Response(
        required=True,
        metadata={"description": "RPC Response", "example": RPC_RESPONSE_EXAMPLE},
    )

    thread_id = fields.String(
        required=True,
        metadata={"description": "Thread identifier", "example": UUID4_EXAMPLE},
    )


class DRPCRecordListQuerySchema(OpenAPISchema):
    """Parameters and validators for DIDComm RPC request/response exchange query."""

    connection_id = fields.String(
        required=False,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    thread_id = fields.String(
        required=False,
        metadata={"description": "Thread identifier", "example": UUID4_EXAMPLE},
    )

    state = fields.String(
        required=False,
        validate=validate.OneOf(
            [
                DRPCRecord.STATE_REQUEST_SENT,
                DRPCRecord.STATE_REQUEST_RECEIVED,
                DRPCRecord.STATE_COMPLETED,
            ]
        ),
        metadata={"description": "RPC state"},
    )


class DRPCRecordListSchema(OpenAPISchema):
    """Response schema for getting all DIDComm RPC request/response exchanges."""

    results = fields.List(
        fields.Nested(DRPCRecordSchema()),
        required=True,
        metadata={"description": "List of DIDComm RPC request/reponse exchanges"},
    )


class DRPCRecordMatchInfoSchema(OpenAPISchema):
    """Parameters and validators for DIDComm RPC request/response exchange match."""

    record_id = fields.String(
        required=True,
        metadata={
            "description": "DRPC record identifier",
        },
    )


@docs(
    tags=["drpc"],
    summary="Send a DIDComm RPC request message",
)
@request_schema(DRPCRequestSchema())
@response_schema(DRPCRequestMessageSchema(), 200)
async def drpc_send_request(request: web.BaseRequest):
    """Request handler for sending a DIDComm RPC request message."""

    LOGGER.debug("Recieved DRPC send request >>>")

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()
    connection_id = body["connection_id"]
    request = body["request"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            connection = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err

        if connection.is_ready:
            request_record = DRPCRecord(
                request=request, state=DRPCRecord.STATE_REQUEST_SENT
            )

            # Save the request in the wallet
            record = StorageRecord(
                type=DRPCRecord.RECORD_TYPE,
                value=json.dumps(request_record.serialize()),
            )

            try:
                await storage.add_record(record)
            except StorageError as err:
                raise web.HTTPInternalServerError(reason=err.roll_up) from err

            # Create a new message to the recipient
            msg = DRPCRequestMessage(
                connection_id=connection_id,
                request=request_record.request,
                state=request_record.state,
            )

            try:
                await storage.update_record(
                    record,
                    value=json.dumps(request_record.serialize()),
                    tags={
                        "connection_id": connection_id,
                        "thread_id": msg._id,
                    },
                )
            except StorageError as err:
                raise web.HTTPInternalServerError(reason=err.roll_up) from err

            await outbound_handler(msg, connection_id=connection_id)
            return web.json_response(msg.serialize())

        raise web.HTTPForbidden(reason=f"Connection {connection_id} is not ready")


@docs(
    tags=["drpc"],
    summary="Send a DIDComm RPC response message",
)
@request_schema(DRPCResponseSchema())
@response_schema(DRPCResponseMessageSchema(), 200)
async def drpc_send_response(request: web.BaseRequest):
    """Request handler for sending a DIDComm RPC response message."""

    LOGGER.debug("Recieved DRPC send response >>>")

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()
    connection_id = body["connection_id"]
    thread_id = body["thread_id"]
    response = body["response"]

    async with context.session() as session:
        try:
            connection = await ConnRecord.retrieve_by_id(session, connection_id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err

        if connection.is_ready:
            try:
                response_record = await DRPCRecord.retrieve_by_connection_and_thread(
                    session, connection_id, thread_id
                )
            except StorageNotFoundError as err:
                raise web.HTTPNotFound(reason=err.roll_up) from err

            # Update the response_record with the response and state
            response_record.response = response
            response_record.state = DRPCRecord.STATE_COMPLETED

            storage = session.inject(BaseStorage)
            value = json.dumps(response_record.serialize())
            tags = {
                "connection_id": connection_id,
                "thread_id": thread_id,
            }
            try:
                await storage.update_record(response_record.storage_record, value, tags)
            except StorageError as err:
                raise web.HTTPInternalServerError(reason=err.roll_up) from err

            # Create a new message to the recipient
            msg = DRPCResponseMessage(
                connection_id=connection_id,
                response=response_record.response,
                state=response_record.state,
            )
            msg.assign_thread_id(thread_id)

            await outbound_handler(msg, connection_id=connection_id)
            return web.json_response(msg.serialize())

        raise web.HTTPForbidden(reason=f"Connection {connection_id} is not ready")


@docs(
    tags=["drpc"],
    summary="Get all DIDComm RPC records",
)
@querystring_schema(DRPCRecordListQuerySchema())
@response_schema(DRPCRecordListSchema(), 200)
async def drpc_get_records(request: web.BaseRequest):
    """Request handler for getting all DIDComm RPC records."""

    LOGGER.debug("Recieved DRPC get records >>>")

    context: AdminRequestContext = request["context"]

    tag_filter = {}
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]
    if "connection_id" in request.query and request.query["connection_id"] != "":
        tag_filter["connection_id"] = request.query["connection_id"]

    post_filter = {}
    if "state" in request.query and request.query["state"] != "":
        post_filter["state"] = request.query["state"]

    async with context.session() as session:
        try:
            storage = session.inject(BaseStorage)
            rows = await storage.find_all_records(
                DRPCRecord.RECORD_TYPE,
                DRPCRecord.prefix_tag_filter(tag_filter),
                {"forUpdate": False, "retrieveTags": False},
            )
            results = []
            for record in rows:
                val = json.loads(record.value)
                if match_post_filter(val, post_filter, positive=True, alt=True):
                    try:
                        drpc_record = DRPCRecord.from_storage(record.id, val)
                        results.append(
                            {
                                **drpc_record.serialize(),
                                "id": record.id,
                                "tags": record.tags,
                            }
                        )
                    except BaseModelError as err:
                        raise BaseModelError(f"{err}, for record id {record.id}")
        except (StorageError, BaseModelError) as err:
            raise web.HTTPInternalServerError(reason=err.roll_up) from err

        return web.json_response({"results": results})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/drpc/request", drpc_send_request)])
    app.add_routes([web.post("/drpc/response", drpc_send_response)])
    app.add_routes([web.get("/drpc/records", drpc_get_records, allow_head=False)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {"name": "drpc", "description": "DIDComm RPC between Aries agents"}
    )
