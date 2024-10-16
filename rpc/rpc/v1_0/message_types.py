"""Message types for DIDComm RPC v1.0."""

from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix

# Message types
DRPC_REQUEST = "drpc/1.0/request"
DRPC_RESPONSE = "drpc/1.0/response"

PROTOCOL_PACKAGE = "rpc.v1_0"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        DRPC_REQUEST: f"{PROTOCOL_PACKAGE}.messages.DRPCRequestMessage",
        DRPC_RESPONSE: f"{PROTOCOL_PACKAGE}.messages.DRPCResponseMessage",
    }
)
