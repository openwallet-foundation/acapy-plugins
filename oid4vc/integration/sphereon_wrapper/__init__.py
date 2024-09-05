"""AFJ Wrapper."""

from jrpc_client import BaseSocketTransport, JsonRpcClient


class SphereaonWrapper:
    """Sphereon Wrapper."""

    def __init__(self, transport: BaseSocketTransport, client: JsonRpcClient):
        """Initialize the wrapper."""
        self.transport = transport
        self.client = client

    async def start(self):
        """Start the wrapper."""
        await self.transport.connect()
        await self.client.start()

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

    async def test(self) -> dict:
        """Hit test method."""
        return await self.client.request("test")

    async def accept_credential_offer(self, offer: str):
        """Accpet offer."""
        return await self.client.request("acceptCredentialOffer", offer=offer)
