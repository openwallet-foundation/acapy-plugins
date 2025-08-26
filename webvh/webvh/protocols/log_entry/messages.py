"""Witness messages."""

from acapy_agent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from .message_types import HANDLER_MODULE, WITNESS_REQUEST, WITNESS_RESPONSE


class WitnessRequest(AgentMessage):
    """Request witness of a log entry."""

    class Meta:
        """RequestWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessRequestHandler"
        message_type = WITNESS_REQUEST
        schema_class = "WitnessRequestSchema"

    def __init__(self, document: dict, request_id: str = None, **kwargs):
        """Initialize RequestWitness."""
        super().__init__(**kwargs)
        self.request_id = request_id
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

    request_id = fields.Str(
        required=False,
        metadata={"description": "the witness request id"},
    )


class WitnessResponse(AgentMessage):
    """Response witness of a log entry."""

    class Meta:
        """ResponseWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessResponseHandler"
        message_type = WITNESS_RESPONSE
        schema_class = "WitnessResponseSchema"

    def __init__(
        self,
        state: str,
        document: dict,
        witness_proof: dict = None,
        request_id: str = None,
        **kwargs,
    ):
        """Initialize ResponseWitness."""
        super().__init__(**kwargs)
        self.state = state
        self.document = document
        self.witness_proof = witness_proof
        self.request_id = request_id


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

    request_id = fields.Str(
        required=False,
        metadata={"description": "the witness request id"},
    )
