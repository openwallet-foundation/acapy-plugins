"""Message types for did:webvh witnessing."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

PROTOCOL = "did-webvh-witness/1.0"
PROTOCOL_PACKAGE = "webvh.did"

# Message types
WITNESS_REQUEST = f"{PROTOCOL}/witness_request"
WITNESS_RESPONSE = f"{PROTOCOL}/witness_response"


MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        WITNESS_REQUEST: f"{PROTOCOL_PACKAGE}.messages.witness.WitnessRequest",  # noqa: E501
        WITNESS_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.witness.WitnessResponse",  # noqa: E501
    }
)
