"""Endorsement messages."""

from marshmallow import EXCLUDE, fields

from acapy_agent.messaging.agent_message import AgentMessage, AgentMessageSchema
from ..message_types import ENDORSEMENT_REQUEST, ENDORSEMENT_RESPONSE

HANDLER_MODULE = "webvh.did.handlers.handler"


class EndorsementRequest(AgentMessage):
    """Request endorsement of a log entry."""

    class Meta:
        """RequestEndorsement metadata."""

        handler_class = HANDLER_MODULE + ".EndorsementRequestHandler"
        message_type = ENDORSEMENT_REQUEST
        schema_class = "EndorsementRequestSchema"

    def __init__(self, document: dict, **kwargs):
        """Initialize RequestEndorsement."""
        super().__init__(**kwargs)
        self.document = document


class EndorsementRequestSchema(AgentMessageSchema):
    """RequestEndorsement schema."""

    class Meta:
        """RequestEndorsement schema metadata."""

        model_class = EndorsementRequest
        unknown = EXCLUDE

    model_class = EndorsementRequest

    document = fields.Dict(
        required=True,
        metadata={"description": "document to endorse"},
    )


class EndorsementResponse(AgentMessage):
    """Response endorsement of a log entry."""

    class Meta:
        """ResponseEndorsement metadata."""

        handler_class = HANDLER_MODULE + ".EndorsementResponseHandler"
        message_type = ENDORSEMENT_RESPONSE
        schema_class = "EndorsementResponseSchema"

    def __init__(self, state: str, document: dict, **kwargs):
        """Initialize ResponseEndorsement."""
        super().__init__(**kwargs)
        self.state = state
        self.document = document


class EndorsementResponseSchema(AgentMessageSchema):
    """ResponseEndorsement schema."""

    class Meta:
        """ResponseEndorsement schema metadata."""

        model_class = EndorsementResponse
        unknown = EXCLUDE

    model_class = EndorsementResponse

    state = fields.Str(
        required=True,
        metadata={
            "description": "State of the endorsement",
            "example": "pending",
        },
    )
    document = fields.Dict(
        required=False,
        metadata={
            "description": "document to endorse",
        },
    )
