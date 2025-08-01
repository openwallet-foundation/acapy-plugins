"""Witness messages."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix
from acapy_agent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

HANDLER_MODULE = "webvh.protocols.witness_log_entry.handlers"

PROTOCOL = "did-webvh-witness-log-entry/1.0"
PROTOCOL_PACKAGE = "webvh.protocols.witness_log_entry"

# Message types
WITNESS_REQUEST = f"{PROTOCOL}/witness_request"
WITNESS_RESPONSE = f"{PROTOCOL}/witness_response"


MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        WITNESS_REQUEST: f"{PROTOCOL_PACKAGE}.messages.WitnessRequest",  # noqa: E501
        WITNESS_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.WitnessResponse",  # noqa: E501
    }
)


class WitnessRequest(AgentMessage):
    """Request witness of a log entry."""

    class Meta:
        """RequestWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessRequestHandler"
        message_type = WITNESS_REQUEST
        schema_class = "WitnessRequestSchema"

    def __init__(self, document: dict, **kwargs):
        """Initialize RequestWitness."""
        super().__init__(**kwargs)
        self.document = document


class WitnessRequestSchema(AgentMessageSchema):
    """RequestWitness schema."""

    class Meta:
        """RequestWitness schema metadata."""

        model_class = WitnessRequest
        unknown = EXCLUDE

    model_class = WitnessRequest

    document = fields.Dict(
        required=True,
        metadata={"description": "document to witness"},
    )


class WitnessResponse(AgentMessage):
    """Response witness of a log entry."""

    class Meta:
        """ResponseWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessResponseHandler"
        message_type = WITNESS_RESPONSE
        schema_class = "WitnessResponseSchema"

    def __init__(self, state: str, document: dict, witness_proof: dict = None, **kwargs):
        """Initialize ResponseWitness."""
        super().__init__(**kwargs)
        self.state = state
        self.document = document
        self.witness_proof = witness_proof


class WitnessResponseSchema(AgentMessageSchema):
    """ResponseWitness schema."""

    class Meta:
        """ResponseWitness schema metadata."""

        model_class = WitnessResponse
        unknown = EXCLUDE

    model_class = WitnessResponse

    state = fields.Str(
        required=True,
        metadata={
            "description": "State of the witness",
            "example": "pending",
        },
    )
    document = fields.Dict(
        required=False,
        metadata={
            "description": "document to witness",
        },
    )
    witness_proof = fields.Dict(
        required=False,
        metadata={
            "description": "witness proof",
        },
    )
