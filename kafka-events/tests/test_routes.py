"""Test AIO Producer."""
from unittest.mock import MagicMock

import pytest
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.storage.error import StorageError

from kafka_events.routes import post_process_routes, register, stop_kafka, start_kafka
from asynctest import mock, CoroutineMock
from aiohttp import web


async def aux(*args, **kwargs):
    pass


async def raise_exception(*args, **kwargs):
    raise StorageError()


@pytest.fixture
def context():
    """Context fixture."""
    yield AdminRequestContext.test_context()


@pytest.fixture
def web_request(context):
    """Web request fixture."""
    request_dict = {
        "context": context,
        "outbound_message_router": mock.CoroutineMock(),
    }
    request = mock.MagicMock(
        app={},
        match_info={},
        query={},
        json=mock.CoroutineMock(),
        __getitem__=lambda _, k: request_dict[k],
    )
    yield request


@pytest.mark.asyncio
async def test_stop_kafka(web_request):
    with mock.patch("kafka_events.routes.teardown") as teardown:
        teardown.side_effect = aux
        result = await stop_kafka(web_request)
        assert result.reason == "OK"
        assert result.status == 200


@pytest.mark.asyncio
async def test_exception_raised_stop_kafka(web_request):
    with pytest.raises(web.HTTPBadRequest):
        with mock.patch("kafka_events.routes.teardown") as teardown:
            teardown.side_effect = raise_exception
            await stop_kafka(web_request)


@pytest.mark.asyncio
async def test_start_kafka(web_request):
    with mock.patch("kafka_events.routes.start") as start:
        start.side_effect = aux
        result = await start_kafka(web_request)
        assert result.reason == "OK"
        assert result.status == 200


@pytest.mark.asyncio
async def test_exception_raised_start_kafka(web_request):
    with pytest.raises(web.HTTPBadRequest):
        with mock.patch("kafka_events.routes.start") as start:
            start.side_effect = raise_exception
            await start_kafka(web_request)


@pytest.mark.asyncio
async def test_register():
    await register(MagicMock())


@pytest.mark.asyncio
async def test_post_process_routes():
    post_process_routes(MagicMock())
