"""AFJ Wrapper."""

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

    async def openid4vci_accept_offer(self, offer: str):
        """Accept OpenID4VCI credential offer."""
        return await self.client.request(
            "openid4vci.acceptCredentialOffer",
            offer=offer,
        )

    async def openid4vp_accept_request(self, request: str):
        """Accept OpenID4VP presentation (authorization) request."""
        return await self.client.request(
            "openid4vci.acceptAuthorizationRequest",
            request=request,
        )
