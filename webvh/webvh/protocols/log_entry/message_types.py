"""Witness messages."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

HANDLER_MODULE = "webvh.protocols.log_entry.handlers"

PROTOCOL = "log_entry/1.0"

# Message types
WITNESS_REQUEST = f"{PROTOCOL}/witness_request"
WITNESS_RESPONSE = f"{PROTOCOL}/witness_response"

PROTOCOL_PACKAGE = "webvh.protocols.log_entry"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        WITNESS_REQUEST: f"{PROTOCOL_PACKAGE}.messages.WitnessRequest",
        WITNESS_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.WitnessResponse",
    }
)
