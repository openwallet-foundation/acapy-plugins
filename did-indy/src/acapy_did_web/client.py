"""DID Web Server client."""

from aiohttp import ClientSession


class DidWebServerClientError(Exception):
    """Raised on errors in the client."""


class DidWebServerClient:
    """Client to DID Web Server."""

    def __init__(self, base_url: str):
        """Init the client."""
        self.base_url = base_url

    async def put_did(self, name: str, document: dict):
        """Put the DID at the named location on the server."""
        async with ClientSession(self.base_url) as session:
            async with session.put(f"/did/{name}", json=document) as resp:
                if not resp.ok:
                    raise DidWebServerClientError(
                        "Failed to put the document: " + await resp.text()
                    )
