import inspect
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from authlib.oauth2.rfc6749 import OAuth2Request

import tenant.oauth.server as oauth_server
from core.consts import OAuth2Flow


@pytest.mark.asyncio
async def test_save_token_includes_meta_for_pre_auth_flow(monkeypatch):
    monkeypatch.setattr(oauth_server, "_server", None)
    server = oauth_server.get_authorization_server()

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=900)
    response_meta = {
        "c_nonce": "nonce-123",
        "c_nonce_expires_in": 600,
        "authorization_details": [
            {"type": "openid_credential", "locations": ["https://issuer"]}
        ],
    }
    access_stub = SimpleNamespace(
        token="signed-access",
        issued_at=issued_at,
        expires_at=expires_at,
    )

    req = OAuth2Request(method="POST", uri="https://example.org/token")
    ctx = SimpleNamespace(
        token_ctx={
            "flow": OAuth2Flow.PRE_AUTH_CODE,
            "code": "abc",
            "realm": "tenant-a",
        },
        uid="tenant-a",
        db=object(),
    )

    monkeypatch.setattr(oauth_server, "get_context", lambda _req: ctx)
    monkeypatch.setattr(
        oauth_server.TokenService,
        "issue_by_pre_auth_code",
        AsyncMock(return_value=(access_stub, "refresh-token", response_meta)),
    )

    token_payload: dict = {}
    result = server.save_token(token_payload, req)  # type: ignore[arg-type]
    if inspect.isawaitable(result):
        await result  # type: ignore[misc]

    assert token_payload["access_token"] == "signed-access"
    assert token_payload["refresh_token"] == "refresh-token"
    assert token_payload["token_type"] == "Bearer"
    assert token_payload["expires_in"] == pytest.approx(900)
    assert (
        token_payload["authorization_details"] == response_meta["authorization_details"]
    )
    assert token_payload["c_nonce"] == "nonce-123"
    assert token_payload["c_nonce_expires_in"] == 600
    assert "realm" not in token_payload


@pytest.mark.asyncio
async def test_save_token_includes_meta_for_refresh_flow(monkeypatch):
    monkeypatch.setattr(oauth_server, "_server", None)
    server = oauth_server.get_authorization_server()

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=900)
    response_meta = {
        "c_nonce": "nonce-456",
        "c_nonce_expires_in": 300,
    }
    access_stub = SimpleNamespace(
        token="new-access",
        issued_at=issued_at,
        expires_at=expires_at,
    )

    req = OAuth2Request(method="POST", uri="https://example.org/token")
    ctx = SimpleNamespace(
        token_ctx={
            "flow": OAuth2Flow.REFRESH_TOKEN,
            "refresh_token": "old-refresh",
            "realm": "tenant-b",
        },
        uid="tenant-b",
        db=object(),
    )

    monkeypatch.setattr(oauth_server, "get_context", lambda _req: ctx)
    monkeypatch.setattr(
        oauth_server.TokenService,
        "rotate_by_refresh_token",
        AsyncMock(return_value=(access_stub, "rotated-refresh", response_meta)),
    )

    token_payload: dict = {}
    result = server.save_token(token_payload, req)  # type: ignore[arg-type]
    if inspect.isawaitable(result):
        await result  # type: ignore[misc]

    assert token_payload["access_token"] == "new-access"
    assert token_payload["refresh_token"] == "rotated-refresh"
    assert token_payload["token_type"] == "Bearer"
    assert token_payload["c_nonce"] == "nonce-456"
    assert token_payload["c_nonce_expires_in"] == 300
    assert "authorization_details" not in token_payload
    assert "realm" not in token_payload
