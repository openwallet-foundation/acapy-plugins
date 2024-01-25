import logging
from typing import Iterable

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields, post_load

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.connections.models.conn_record import ConnRecord
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import UUID4_EXAMPLE
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError

from rpc.v1_0.models import (
  RPC_REQUEST_EXAMPLE,
  RPC_RESPONSE_EXAMPLE,
  DRPCRequestRecord,
  Request,
  Response
)
from rpc.v1_0.messages import (
    DRPCRequestMessage,
    DRPCRequestMessageSchema,
    DRPCResponseMessageSchema
)

LOGGER = logging.getLogger(__name__)


class DRPCRequest(BaseModel):
    """DIDComm RPC Request Model."""
    
    class Meta:
        schema_class = "DRPCRequestSchema"

    def __init__(self, *, conn_id: str = None, request: dict = None, **kwargs):
        super().__init__(**kwargs)
        self.conn_id = conn_id
        self.request = request


class DRPCResponse(BaseModel):
    """DIDComm RPC Response Model."""
    
    class Meta:
        schema_class = "DRPCResponseSchema"

    def __init__(self, *, conn_id: str = None, response: dict = None, **kwargs):
        super().__init__(**kwargs)
        self.conn_id = conn_id
        self.response = response


class DRPCRequestSchema(BaseModelSchema, OpenAPISchema):
    """Request schema for sending a DIDComm RPC Request."""

    class Meta:
      model_class = "DRPCRequest"

    conn_id = fields.String(
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
      model_class = "DRPCResponse"

    conn_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    response = Response(
        required=True,
        metadata={"description": "RPC Response", "example": RPC_RESPONSE_EXAMPLE},
    )

  
@docs(
    tags=["drpc"], summary="Send a DIDComm RPC request message",
)
@request_schema(DRPCRequestSchema())
@response_schema(DRPCRequestMessageSchema(), 200)
async def drpc_send_request(request: web.BaseRequest):
    """
    Request handler for sending a DIDComm RPC request message.
    """

    LOGGER.debug("Recieved DRPC send request >>>")

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()
    conn_id = body["conn_id"]
    request = body["request"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            connection = await ConnRecord.retrieve_by_id(session, conn_id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err

        if (connection.is_ready):
            request_record = DRPCRequestRecord(request=request)

            # Save the request in the wallet
            record = StorageRecord(
                type=DRPCRequestRecord.RECORD_TYPE,
                value=request_record.serialize()
            )
            try:
                await storage.add_record(record)
            except StorageError as err:
                raise web.HTTPBadRequest(reason=err.roll_up) from err

            # Create a new message to the recipient
            msg = DRPCRequestMessage(conn_id=conn_id,
                                    request=request_record.request,
                                    state=request_record.state)
            # TODO: Uncomment when testing against another agent with drpc enabled
            await outbound_handler(msg, connection_id=conn_id)
            return web.json_response(msg.serialize())
    
        raise web.HTTPForbidden(reason=f"Connection {conn_id} is not ready")


@docs(
    tags=["drpc"], summary="Send a DIDComm RPC response message",
)
@request_schema(DRPCResponseSchema())
@response_schema(DRPCResponseMessageSchema(), 200)
async def drpc_send_response(request: web.BaseRequest):
    """
    Request handler for sending a DIDComm RPC response message.
    """

    LOGGER.debug("Recieved DRPC send response >>>")

    context: AdminRequestContext = request["context"]
    outbound_handler = request["outbound_message_router"]

    body = await request.json()
    conn_id = body["conn_id"]
    response = body["response"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            connection = await ConnRecord.retrieve_by_id(session, conn_id)
        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err

        if (connection.is_ready):
            # TODO:
            pass

            return web.json_response({})
    
        raise web.HTTPForbidden(reason=f"Connection {conn_id} is not ready")


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/drpc/request", drpc_send_request)])
    app.add_routes([web.post("/drpc/response", drpc_send_response)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {"name": "drpc", "description": "DIDComm RPC between Aries agents"}
    )
