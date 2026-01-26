"""AFJ Wrapper."""

from typing import Any, Optional
from jrpc_client import BaseSocketTransport, JsonRpcClient


class CredoWrapper:
    """Credo Wrapper."""

    def __init__(self, transport: BaseSocketTransport, client: JsonRpcClient):
        """Initialize the wrapper."""
        self.transport = transport
        self.client = client

    async def start(self):
        """Start the wrapper."""
        await self.transport.connect()
        await self.client.start()
        await self.client.request("initialize")

    async def stop(self):
        """Stop the wrapper."""
        await self.client.stop()
        await self.transport.close()

    async def __aenter__(self):
        """Start the wrapper when entering the context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Stop the wrapper when exiting the context manager."""
        await self.stop()

    # Credo API
    async def notification_received(
        self, event: Optional[str] = None, *, timeout: int = 5
    ) -> Any:
        event = f"event.{event}" if event else None
        return await self.client.notification_received(event, timeout=timeout)

    async def receive_invitation(self, invitation: str) -> dict:
        """Receive an invitation."""
        return await self.client.request("receiveInvitation", invitation=invitation)

    async def connection_state_changed(self):
        return await self.client.notification_received("event.ConnectionStateChanged")

    async def resolve(self, did: str) -> dict:
        """Resolve a DID."""
        return await self.client.request("resolve", did=did)

    async def credentials_accept_offer(self, record_id: str):
        """Accept a credential offer."""
        return await self.client.request(
            "credentials.acceptOffer", credentialRecordId=record_id
        )

    async def proofs_accept_request(self, record_id: str):
        """Accept a proof request."""
        return await self.client.request(
            "proofs.acceptRequest", proofRecordId=record_id
        )

    async def validate_presentation_definition(self, definition: Any):
        """Validate a presentation definition using Sphereon PEX."""
        return await self.client.request(
            "validatePresentationDefinition", definition=definition
        )
