from typing import Union
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import UUID4_EXAMPLE
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema

from rpc.v1_0.models import (
  RPC_REQUEST_EXAMPLE,
  RPC_RESPONSE_EXAMPLE,
  DRPCRequestRecordSchema,
  DRPCResponseRecordSchema,
  Request,
  Response
)


class DRPCRequestResult(AgentMessage):
    """DIDComm RPC Request Result Agent Message."""

    class Meta:
        schema_class = "DRPCRequestResultSchema"

    def __init__(self, *, state: str = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state


class DRPCResponseResult(AgentMessage):
    """DIDComm RPC Response Result Agent Message."""

    class Meta:
        schema_class = "DRPCResponseResultSchema"

    def __init__(self, *, state: str = None, **kwargs):
        super().__init__(**kwargs)
        self.state = state


class DRPCRequestSchema(OpenAPISchema):
    """Request schema for sending a DIDComm RPC Request."""

    request = Request(
        required=True,
        metadata={"description": "RPC Request", "example": RPC_REQUEST_EXAMPLE},
    )


class DRPCRequestResultSchema(AgentMessageSchema, DRPCRequestRecordSchema):
    """Result schema from sending a DIDComm RPC Request."""

    class Meta:
      model_class = "DRPCRequestResult"

    conn_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )


class DRPCResponseSchema(OpenAPISchema):
    """Request schema for sending a DIDComm RPC Response."""

    response = Response(
        required=True,
        metadata={"description": "RPC Response", "example": RPC_RESPONSE_EXAMPLE},
    )

  
class DRPCResponseResultSchema(AgentMessageSchema, DRPCResponseRecordSchema):
    """Result schema from sending a DIDComm RPC Response."""

    class Meta:
      model_class = "DRPCResponseResult"

    conn_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )


@docs(
    tags=["drpc"], summary="Send a DIDComm RPC request message",
)
@request_schema(DRPCRequestSchema())
@response_schema(DRPCRequestResultSchema(), 200)
async def drpc_send_request(request: web.BaseRequest):
    """
    Request handler for sending a DIDComm RPC request message.
    """
    return web.json_response({})


@docs(
    tags=["drpc"], summary="Send a DIDComm RPC response message",
)
@request_schema(DRPCResponseSchema())
@response_schema(DRPCResponseResultSchema(), 200)
async def drpc_send_response(request: web.BaseRequest):
    """
    Request handler for sending a DIDComm RPC response message.
    """
    return web.json_response({})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/drpc/{conn_id}/request", drpc_send_request)])
    app.add_routes([web.post("/drpc/{conn_id}/response", drpc_send_response)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {"name": "drpc", "description": "DIDComm RPC between connections"}
    )
