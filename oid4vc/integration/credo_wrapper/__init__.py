"""Credo Wrapper."""

from __future__ import annotations

import httpx


class CredoWrapper:
    """Credo Wrapper using HTTP."""

    def __init__(self, base_url: str):
        """Initialize the wrapper."""
        self.base_url = base_url.rstrip("/")
        self.client: httpx.AsyncClient | None = None

    async def start(self):
        """Start the wrapper."""
        self.client = httpx.AsyncClient()
        # Check Credo agent health
        response = await self.client.get(f"{self.base_url}/health", timeout=30.0)
        response.raise_for_status()

    async def stop(self):
        """Stop the wrapper."""
        if self.client:
            await self.client.aclose()
            self.client = None

    def _client(self) -> httpx.AsyncClient:
        if not self.client:
            raise RuntimeError(
                "CredoWrapper not started; use within an async context manager"
            )
        return self.client

    async def __aenter__(self):
        """Start the wrapper when entering the context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Stop the wrapper when exiting the context manager."""
        await self.stop()

    # Credo API

    async def test(self):
        """Test basic connectivity to Credo agent."""
        response = await self._client().get(f"{self.base_url}/health", timeout=30.0)
        response.raise_for_status()
        return response.json()

    async def openid4vci_accept_offer(self, offer: str, holder_did_method: str = "key"):
        """Accept OpenID4VCI credential offer."""
        response = await self._client().post(
            f"{self.base_url}/oid4vci/accept-offer",
            json={"credential_offer": offer, "holder_did_method": holder_did_method},
            timeout=120.0,
        )
        response.raise_for_status()
        return response.json()

    async def openid4vp_accept_request(self, request: str, credentials: list = None):
        """Accept OpenID4VP presentation (authorization) request.

        Args:
            request: The presentation request URI
            credentials: List of credentials to present (can be strings for mso_mdoc or dicts)
        """
        payload = {"request_uri": request}
        if credentials:
            payload["credentials"] = credentials

        response = await self._client().post(
            f"{self.base_url}/oid4vp/present",
            json=payload,
            timeout=120.0,
        )
        response.raise_for_status()
        return response.json()
