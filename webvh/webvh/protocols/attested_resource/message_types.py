"""Witness messages."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

HANDLER_MODULE = "didwebvh.protocols.attested_resource.handlers"

PROTOCOL = "attested_resource/1.0"

# Message types
WITNESS_REQUEST = f"{PROTOCOL}/request"
WITNESS_RESPONSE = f"{PROTOCOL}/response"

PROTOCOL_PACKAGE = "didwebvh.protocols.attested_resource"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        WITNESS_REQUEST: f"{PROTOCOL_PACKAGE}.messages.request.WitnessRequest",
        WITNESS_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.response.WitnessResponse",
    }
)
