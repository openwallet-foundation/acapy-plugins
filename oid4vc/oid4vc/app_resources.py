"""App resources."""

import logging
import aiohttp
import asyncio

from .config import Config

LOGGER = logging.getLogger(__name__)


class AppResources:
    """Application-wide resources like HTTP client and cleanup tasks."""

    _auth_server_url: str | None = None
    _http_client: aiohttp.ClientSession | None = None
    _cleanup_task: asyncio.Task | None = None
    _client_shutdown: bool = False

    @classmethod
    async def startup(cls, config: Config | None = None):
        """Initialize resources."""
        if config and config.auth_server_url:
            cls._auth_server_url = config.auth_server_url
            LOGGER.info("Initializing HTTP client...")
            cls._http_client = aiohttp.ClientSession()
            # LOGGER.info("Starting up cleanup task...")
            # cls._cleanup_task = asyncio.create_task(cls._background_cleanup())

    @classmethod
    async def shutdown(cls):
        """Clean up resources."""
        if cls._cleanup_task:
            LOGGER.info("Shutting down cleanup task...")
            cls._cleanup_task.cancel()
            try:
                await cls._cleanup_task
            except asyncio.CancelledError:
                pass
            cls._cleanup_task = None
        if cls._http_client:
            LOGGER.info("Closing HTTP client...")
            await cls._http_client.close()
            cls._http_client = None
        cls._client_shutdown = True

    @classmethod
    def get_http_client(cls) -> aiohttp.ClientSession:
        """Get the initialized HTTP client."""
        if cls._client_shutdown:
            raise RuntimeError("HTTP client was shut down and cannot be re-initialized")
        if cls._auth_server_url and cls._http_client is None:
            LOGGER.warning("Warning: HTTP client was None, re-initializing.")
            cls._http_client = aiohttp.ClientSession()
        if cls._http_client is None:
            raise RuntimeError("HTTP client is not initialized")
        return cls._http_client

    @classmethod
    async def _background_cleanup(cls):
        """Background task for periodic cleanup."""
        while True:
            try:
                await cleanup_expired_nonces()
            except Exception as e:
                LOGGER.exception(f"Nonce cleanup error: {e}")

            await asyncio.sleep(3600)  # Run every hour


async def cleanup_expired_nonces():
    """Cleanup expired nonces from storage."""
    pass
