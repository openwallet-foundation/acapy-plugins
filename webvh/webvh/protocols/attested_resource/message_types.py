"""Witness messages."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

HANDLER_MODULE = "webvh.protocols.attested_resource.handlers"

PROTOCOL = "attested_resource/1.0"

# Message types
WITNESS_REQUEST = f"{PROTOCOL}/request"
WITNESS_RESPONSE = f"{PROTOCOL}/response"

PROTOCOL_PACKAGE = "webvh.protocols.attested_resource"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        WITNESS_REQUEST: f"{PROTOCOL_PACKAGE}.messages.WitnessRequest",
        WITNESS_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.WitnessResponse",
    }
)
