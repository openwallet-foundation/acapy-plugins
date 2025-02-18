"""Witness messages."""

from acapy_agent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import WITNESS_REQUEST, WITNESS_RESPONSE

HANDLER_MODULE = "webvh.did.handlers.handler"


class WitnessRequest(AgentMessage):
    """Request witness of a log entry."""

    class Meta:
        """RequestWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessRequestHandler"
        message_type = WITNESS_REQUEST
        schema_class = "WitnessRequestSchema"

    def __init__(self, document: dict, parameters: dict, **kwargs):
        """Initialize RequestWitness."""
        super().__init__(**kwargs)
        self.document = document
        self.parameters = parameters


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
    parameters = fields.Dict(
        required=False,
        metadata={
            "description": "parameters for the initial did",
        },
    )


class WitnessResponse(AgentMessage):
    """Response witness of a log entry."""

    class Meta:
        """ResponseWitness metadata."""

        handler_class = HANDLER_MODULE + ".WitnessResponseHandler"
        message_type = WITNESS_RESPONSE
        schema_class = "WitnessResponseSchema"

    def __init__(self, state: str, document: dict, parameters: dict, **kwargs):
        """Initialize ResponseWitness."""
        super().__init__(**kwargs)
        self.state = state
        self.document = document
        self.parameters = parameters


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
    parameters = fields.Dict(
        required=False,
        metadata={
            "description": "parameters for the initial did",
        },
    )
