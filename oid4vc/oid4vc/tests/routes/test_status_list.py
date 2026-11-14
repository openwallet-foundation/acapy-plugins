from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web

from oid4vc.public_routes.status_list import get_status_list
from oid4vc.status_handler import StatusHandler


def _request(context: AdminRequestContext):
    request = MagicMock()
    request.__getitem__ = lambda _, key: {"context": context}[key]
    request.match_info = {"list_number": "1"}
    return request


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token, media_type, content_type, body",
    [
        (
            b"\xd2\x84",
            "application/statuslist+cwt",
            "application/statuslist+cwt",
            b"\xd2\x84",
        ),
        ("a.b.c", "application/statuslist+jwt", "application/statuslist+jwt", b"a.b.c"),
        ("a.b.c", None, "text/plain", b"a.b.c"),
    ],
)
async def test_status_list_served_with_media_type(
    context, token, media_type, content_type, body
):
    handler = MagicMock(StatusHandler)
    handler.get_status_list = AsyncMock(return_value=(token, media_type))
    context.injector.bind_instance(StatusHandler, handler)

    response = await get_status_list(_request(context))

    handler.get_status_list.assert_awaited_once_with(context, "1")
    assert response.content_type == content_type
    assert response.body == body


@pytest.mark.asyncio
async def test_older_handler_token_served_as_text(context):
    handler = MagicMock(StatusHandler)
    handler.get_status_list = AsyncMock(return_value="a.b.c")
    context.injector.bind_instance(StatusHandler, handler)

    response = await get_status_list(_request(context))

    assert response.content_type == "text/plain"
    assert response.body == b"a.b.c"


@pytest.mark.asyncio
async def test_unconfigured_status_handler_returns_not_found(context):
    status_handler = StatusHandler(context)
    status_handler.handler = None
    context.injector.bind_instance(StatusHandler, status_handler)

    with pytest.raises(web.HTTPNotFound):
        await get_status_list(_request(context))
