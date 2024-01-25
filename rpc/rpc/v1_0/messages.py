"""Agent Messages for DIDComm RPC v1.0."""

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.valid import UUID4_EXAMPLE
from marshmallow import fields, validate

from rpc.v1_0.message_types import DRPC_REQUEST, DRPC_RESPONSE, PROTOCOL_PACKAGE
from rpc.v1_0.models import (
    RPC_REQUEST_EXAMPLE,
    RPC_RESPONSE_EXAMPLE,
    DRPCRecord,
    Request,
    Response,
)


class DRPCRequestMessage(AgentMessage):
    """DIDComm RPC Request Agent Message."""

    class Meta:
        """DRPCRequestMessage metadata."""

        schema_class = "DRPCRequestMessageSchema"
        message_type = DRPC_REQUEST
        handler_class = f"{PROTOCOL_PACKAGE}.handlers.DRPCRequestHandler"

    def __init__(
        self, *, conn_id: str = None, request: dict = None, state: str = None, **kwargs
    ):
        """Initialize DIDComm RPC Request Message."""

        super().__init__(**kwargs)
        self.conn_id = conn_id
        self.request = request
        self.state = state


class DRPCResponseMessage(AgentMessage):
    """DIDComm RPC Response Agent Message."""

    class Meta:
        """DRPCResponseMessage metadata."""

        schema_class = "DRPCResponseMessageSchema"
        message_type = DRPC_RESPONSE
        handler_class = f"{PROTOCOL_PACKAGE}.handlers.DRPCResponseHandler"

    def __init__(self, *, conn_id: str, response: dict, state: str, **kwargs):
        """Initialize DIDComm RPC Response Message."""

        super().__init__(**kwargs)
        self.conn_id = conn_id
        self.response = response
        self.state = state


class DRPCRequestMessageSchema(AgentMessageSchema):
    """Agent Message schema from sending a DIDComm RPC Request."""

    class Meta:
        """DRPCRequestMessageSchema metadata."""

        model_class = "DRPCRequestMessage"

    conn_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    request = Request(
        required=True,
        error_messages={"null": "RPC request cannot be empty."},
        metadata={"description": "RPC request", "example": RPC_REQUEST_EXAMPLE},
    )

    state = fields.String(
        required=True,
        validate=validate.OneOf(
            [DRPCRecord.STATE_REQUEST_SENT, DRPCRecord.STATE_COMPLETED]
        ),
        metadata={"description": "RPC state", "example": DRPCRecord.STATE_REQUEST_SENT},
    )


class DRPCResponseMessageSchema(AgentMessageSchema):
    """Agent Message schema from sending a DIDComm RPC Response."""

    class Meta:
        """DRPCResponseMessageSchema metadata."""

        model_class = "DRPCResponseMessage"

    conn_id = fields.String(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )

    response = Response(
        required=False,
        metadata={"description": "RPC response", "example": RPC_RESPONSE_EXAMPLE},
        missing=None,
    )

    state = fields.String(
        required=True,
        validate=validate.OneOf(
            [DRPCRecord.STATE_REQUEST_RECEIVED, DRPCRecord.STATE_COMPLETED]
        ),
        metadata={
            "description": "RPC state",
            "example": DRPCRecord.STATE_REQUEST_RECEIVED,
        },
    )
