from types import SimpleNamespace
from typing import Any, cast

import pytest
from authlib.oauth2.rfc6749 import AuthorizationServer, OAuth2Request

from tenant.oauth.grants import PreAuthorizedCodeGrant, RotatingRefreshTokenGrant


class DummyServer(AuthorizationServer):
    def __init__(self):
        super().__init__()
        self.saved = None

    async def save_token(self, token, request):  # type: ignore[override]
        self.saved = (token, request)


def make_request(data: dict, *, url: str = "https://example.org/token") -> OAuth2Request:
    req = OAuth2Request(method="POST", uri=url)
    cast(Any, req).payload = SimpleNamespace(data=data, grant_type=data.get("grant_type"))
    return req


@pytest.mark.asyncio
async def test_pre_auth_grant_create_token_response(monkeypatch):
    server = DummyServer()
    request = make_request({"pre-authorized_code": "abc", "user_pin": "123"})
    extra_ctx = SimpleNamespace(uid="tenant-1", db=object(), token_ctx={})
    monkeypatch.setattr("tenant.oauth.grants.get_context", lambda _req: extra_ctx)
    monkeypatch.setattr(
        "tenant.oauth.grants.update_context",
        lambda req, token_ctx: extra_ctx.token_ctx.update(token_ctx),
    )

    grant = PreAuthorizedCodeGrant(request, server)
    await grant.validate_token_request()

    status, body, headers = await grant.create_token_response()

    assert status == 200
    assert body == {}
    assert headers == []
    assert extra_ctx.token_ctx.get("flow") == "pre_auth_code"
    assert extra_ctx.token_ctx.get("realm") == "tenant-1"
    assert extra_ctx.token_ctx.get("code") == "abc"
    assert extra_ctx.token_ctx.get("user_pin") == "123"
    assert server.saved is not None and server.saved[0] == {}


@pytest.mark.asyncio
async def test_pre_auth_grant_missing_uid(monkeypatch):
    server = DummyServer()
    request = make_request(
        {"pre-authorized_code": "abc"}, url="https://example.org/tenants/tenant-1/token"
    )
    monkeypatch.setattr(
        "tenant.oauth.grants.get_context",
        lambda _req: SimpleNamespace(uid=None, db=object()),
    )
    monkeypatch.setattr("tenant.oauth.grants.update_context", lambda req, token_ctx: None)

    grant = PreAuthorizedCodeGrant(request, server)
    await grant.validate_token_request()

    status, _, _ = await grant.create_token_response()
    assert status == 200


@pytest.mark.asyncio
async def test_refresh_grant_create_token_response(monkeypatch):
    server = DummyServer()
    request = make_request({"refresh_token": "rt"})
    extra_ctx = SimpleNamespace(uid="tenant-2", db=object(), token_ctx={})
    monkeypatch.setattr("tenant.oauth.grants.get_context", lambda _req: extra_ctx)
    monkeypatch.setattr(
        "tenant.oauth.grants.update_context",
        lambda req, token_ctx: extra_ctx.token_ctx.update(token_ctx),
    )

    grant = RotatingRefreshTokenGrant(request, server)
    await grant.validate_token_request()

    status, body, headers = await grant.create_token_response()

    assert status == 200
    assert body == {}
    assert headers == []
    assert extra_ctx.token_ctx.get("flow") == "refresh_token"
    assert extra_ctx.token_ctx.get("refresh_token") == "rt"
    assert extra_ctx.token_ctx.get("realm") == "tenant-2"
    assert server.saved is not None and server.saved[0] == {}
