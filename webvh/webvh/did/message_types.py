"""Message types for did:webvh endorsement."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

PROTOCOL = "did-webvh-endorsement/1.0"
PROTOCOL_PACKAGE = "webvh.did"

# Message types
ENDORSEMENT_REQUEST = f"{PROTOCOL}/endorse"
ENDORSEMENT_RESPONSE = f"{PROTOCOL}/endorse_response"


MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        ENDORSEMENT_REQUEST: f"{PROTOCOL_PACKAGE}.messages.endorsement.EndorsementRequest", # noqa: E501
        ENDORSEMENT_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.endorsement.EndorsementResponse", # noqa: E501
    }
)
