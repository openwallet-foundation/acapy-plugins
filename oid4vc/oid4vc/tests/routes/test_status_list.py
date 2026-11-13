from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, create_autospec

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.jwt import dict_to_b64
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from multidict import CIMultiDict

from oid4vc.public_routes.status_list import get_status_list
from oid4vc.status_handler import StatusHandler


def _jwt(typ: str) -> str:
    return f"{dict_to_b64({'typ': typ, 'alg': 'ES256'})}.e30.c2ln"


@pytest.fixture
def handler(context: AdminRequestContext):
    handler = MagicMock(StatusHandler)
    context.injector.bind_instance(StatusHandler, handler)
    yield handler


def _request(context: AdminRequestContext, accept=None):
    request = MagicMock()
    request.__getitem__ = lambda _, k: {"context": context}[k]
    request.match_info = {"list_number": "1"}
    request.headers = CIMultiDict({"Accept": accept} if accept else {})
    return request


@pytest.mark.asyncio
async def test_ietf_jwt_served_as_statuslist_jwt(context, handler):
    token = _jwt("statuslist+jwt")
    handler.get_status_list = AsyncMock(return_value=token)

    response = await get_status_list(_request(context))

    handler.get_status_list.assert_awaited_once_with(context, "1", token_format="jwt")
    assert response.headers["Content-Type"] == "application/statuslist+jwt"
    assert response.headers["Vary"] == "Accept"
    assert response.body == token.encode()


@pytest.mark.asyncio
async def test_cwt_served_as_statuslist_cwt(context, handler):
    handler.get_status_list = AsyncMock(return_value=b"\xd2\x84")

    response = await get_status_list(
        _request(context, accept="application/statuslist+cwt")
    )

    handler.get_status_list.assert_awaited_once_with(context, "1", token_format="cwt")
    assert response.headers["Content-Type"] == "application/statuslist+cwt"
    assert response.headers["Vary"] == "Accept"
    assert response.body == b"\xd2\x84"


@pytest.mark.asyncio
async def test_other_tokens_served_as_text(context, handler):
    token = _jwt("JWT")
    handler.get_status_list = AsyncMock(return_value=token)

    response = await get_status_list(_request(context))

    assert response.content_type == "text/plain"
    assert response.text == token


@pytest.mark.asyncio
async def test_repeated_accept_fields_are_combined(context, handler):
    handler.get_status_list = AsyncMock(return_value=_jwt("statuslist+jwt"))
    headers = CIMultiDict(
        [
            ("Accept", "application/statuslist+jwt;q=0.1"),
            ("Accept", "application/statuslist+cwt;q=1"),
        ]
    )

    async def dispatch(request):
        request["context"] = context
        return await get_status_list(request)

    app = web.Application()
    app.router.add_get("/status/{list_number}", dispatch)
    async with TestClient(TestServer(app)) as client:
        response = await client.get("/status/1", headers=headers)
        assert response.status == 200

    handler.get_status_list.assert_awaited_once_with(context, "1", token_format="cwt")


@pytest.mark.asyncio
async def test_legacy_backend_falls_back_to_jwt(context):
    token = _jwt("statuslist+jwt")

    async def legacy_backend(context, list_number):
        return token

    get_token = create_autospec(legacy_backend, return_value=token)
    status_handler = StatusHandler(context)
    status_handler.handler = SimpleNamespace(get_status_list_token=get_token)
    context.injector.bind_instance(StatusHandler, status_handler)

    response = await get_status_list(
        _request(context, accept="application/statuslist+cwt")
    )

    get_token.assert_awaited_once_with(context, "1")
    assert response.headers["Content-Type"] == "application/statuslist+jwt"
    assert response.body == token.encode()


@pytest.mark.asyncio
async def test_keyword_only_backend_receives_format(context):
    async def formatted_backend(context, list_number, *, token_format="jwt"):
        return "token"

    get_token = create_autospec(formatted_backend, return_value="token")
    status_handler = StatusHandler(context)
    status_handler.handler = SimpleNamespace(get_status_list_token=get_token)

    assert (
        await status_handler.get_status_list(context, "1", token_format="cwt") == "token"
    )
    get_token.assert_awaited_once_with(context, "1", token_format="cwt")


@pytest.mark.asyncio
@pytest.mark.parametrize("supports_format", [False, True])
async def test_backend_type_error_is_not_retried(context, supports_format):
    async def legacy_backend(context, list_number):
        return "token"

    async def formatted_backend(context, list_number, *, token_format="jwt"):
        return "token"

    get_token = create_autospec(
        formatted_backend if supports_format else legacy_backend,
        side_effect=TypeError("backend signing failed"),
    )
    status_handler = StatusHandler(context)
    status_handler.handler = SimpleNamespace(get_status_list_token=get_token)

    with pytest.raises(TypeError, match="backend signing failed"):
        await status_handler.get_status_list(context, "1", token_format="cwt")

    get_token.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "accept, token_format",
    [
        (None, "jwt"),
        ("application/statuslist+cwt", "cwt"),
        ("Application/Statuslist+Cwt", "cwt"),
        ("application/statuslist+jwt;q=0.1, application/statuslist+cwt;q=1", "cwt"),
        ("application/statuslist+cwt;q=0.9, */*;q=0.1", "cwt"),
        ("application/statuslist+jwt, application/statuslist+cwt;q=0", "jwt"),
        ("application/statuslist+jwt;q=1, application/statuslist+cwt;q=0.1", "jwt"),
        ("application/statuslist+cwt, application/statuslist+jwt", "jwt"),
        ("*/*", "jwt"),
        ("application/*", "jwt"),
        ("application/statuslist+cwt;q=0, */*;q=1", "jwt"),
        ("application/statuslist+cwt;q=bogus", "jwt"),
        ("application/not-statuslist+cwt", "jwt"),
    ],
)
async def test_accept_negotiation_selects_backend_format(context, accept, token_format):
    token = b"\xd2\x84" if token_format == "cwt" else _jwt("statuslist+jwt")

    async def formatted_backend(context, list_number, *, token_format="jwt"):
        return token

    get_token = create_autospec(formatted_backend, return_value=token)
    status_handler = StatusHandler(context)
    status_handler.handler = SimpleNamespace(get_status_list_token=get_token)
    context.injector.bind_instance(StatusHandler, status_handler)

    response = await get_status_list(_request(context, accept=accept))

    get_token.assert_awaited_once_with(context, "1", token_format=token_format)
    assert response.content_type == f"application/statuslist+{token_format}"
    assert response.headers["Vary"] == "Accept"
    assert response.body == (token if isinstance(token, bytes) else token.encode())
