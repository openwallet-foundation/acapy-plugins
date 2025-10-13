import asyncio

import aiohttp
import pytest

from oid4vc.app_resources import AppResources


@pytest.mark.asyncio
async def test_startup_and_shutdown(monkeypatch, config):
    await AppResources.startup(config)
    client = AppResources.get_http_client()
    assert isinstance(client, aiohttp.ClientSession)
    await AppResources.shutdown()
    # After shutdown, client should be None
    with pytest.raises(RuntimeError):
        AppResources.get_http_client()


@pytest.mark.asyncio
async def test_background_cleanup(monkeypatch):
    # Patch cleanup_expired_nonces to track calls
    called = {}

    async def fake_cleanup():
        called["ran"] = True

    monkeypatch.setattr("oid4vc.app_resources.cleanup_expired_nonces", fake_cleanup)
    # Run the background cleanup task for one iteration
    task = asyncio.create_task(AppResources._background_cleanup())
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert called.get("ran")
