"""Agent Messages for DIDComm RPC v1.0."""

from acapy_agent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import ValidationError, pre_dump

from rpc.v1_0.message_types import DRPC_REQUEST, DRPC_RESPONSE, PROTOCOL_PACKAGE
from rpc.v1_0.models import RPC_REQUEST_EXAMPLE, RPC_RESPONSE_EXAMPLE, Request, Response


class DRPCRequestMessage(AgentMessage):
    """DIDComm RPC Request Agent Message."""

    class Meta:
        """DRPCRequestMessage metadata."""

        schema_class = "DRPCRequestMessageSchema"
        message_type = DRPC_REQUEST
        handler_class = f"{PROTOCOL_PACKAGE}.handlers.DRPCRequestHandler"

    def __init__(
        self,
        *,
        request: dict = None,
        **kwargs,
    ):
        """Initialize DIDComm RPC Request Message."""

        super().__init__(**kwargs)
        self.request = request


class DRPCResponseMessage(AgentMessage):
    """DIDComm RPC Response Agent Message."""

    class Meta:
        """DRPCResponseMessage metadata."""

        schema_class = "DRPCResponseMessageSchema"
        message_type = DRPC_RESPONSE
        handler_class = f"{PROTOCOL_PACKAGE}.handlers.DRPCResponseHandler"

    def __init__(
        self,
        *,
        response: dict,
        **kwargs,
    ):
        """Initialize DIDComm RPC Response Message."""

        super().__init__(**kwargs)
        self.response = response


class DRPCRequestMessageSchema(AgentMessageSchema):
    """Agent Message schema from sending a DIDComm RPC Request."""

    class Meta:
        """DRPCRequestMessageSchema metadata."""

        model_class = "DRPCRequestMessage"

    request = Request(
        required=True,
        error_messages={"null": "RPC request cannot be empty."},
        metadata={"description": "RPC request", "example": RPC_REQUEST_EXAMPLE},
    )


class DRPCResponseMessageSchema(AgentMessageSchema):
    """Agent Message schema from sending a DIDComm RPC Response."""

    class Meta:
        """DRPCResponseMessageSchema metadata."""

        model_class = "DRPCResponseMessage"

    response = Response(
        required=True,
        error_messages={"null": "RPC response cannot be null."},
        metadata={"description": "RPC response", "example": RPC_RESPONSE_EXAMPLE},
    )

    @pre_dump
    def check_thread_deco(self, obj, **kwargs):
        """Thread decorator, and its thid, are mandatory."""
        if not obj._decorators.to_dict().get("~thread", {}).keys() >= {"thid"}:
            raise ValidationError("Missing required field(s) in thread decorator")
        return obj
