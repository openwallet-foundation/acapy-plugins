from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from authlib.oauth2.rfc6749 import AuthorizationServer, OAuth2Request
from fastapi import HTTPException

from tenant.oauth.grants import PreAuthorizedCodeGrant, RotatingRefreshTokenGrant
from tenant.services.attestation_service import AttestationLookupError


class DummyServer(AuthorizationServer):
    def __init__(self):
        super().__init__()
        self.saved = None

    async def save_token(self, token, request):  # type: ignore[override]
        self.saved = (token, request)


def make_request(
    data: dict,
    *,
    url: str = "https://example.org/token",
    headers: dict[str, str] | None = None,
) -> OAuth2Request:
    req = OAuth2Request(method="POST", uri=url, headers=headers)
    cast(Any, req).payload = SimpleNamespace(data=data, grant_type=data.get("grant_type"))
    return req


@pytest.mark.asyncio
async def test_pre_auth_grant_create_token_response(monkeypatch):
    server = DummyServer()
    request = make_request({"pre-authorized_code": "abc", "tx_code": "123"})
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
    assert extra_ctx.token_ctx.get("tx_code") == "123"
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


@pytest.mark.asyncio
async def test_disabled_security_features_skip_validation(monkeypatch):
    server = DummyServer()
    request = make_request({"pre-authorized_code": "abc"})
    attestation_validator = AsyncMock()
    monkeypatch.setattr("tenant.oauth.grants.settings.ATTESTATION_ENABLED", False)
    monkeypatch.setattr(
        "tenant.oauth.grants.validate_client_attestation", attestation_validator
    )

    grant = PreAuthorizedCodeGrant(request, server)
    await grant.validate_token_request()

    attestation_validator.assert_not_awaited()
    assert grant._attestation_meta is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "required", "expected_required"),
    [
        (False, False, None),
        (True, False, False),
        (True, True, True),
    ],
)
async def test_attestation_policy_matrix(
    monkeypatch, enabled, required, expected_required
):
    server = DummyServer()
    request = make_request(
        {"pre_authorized_code": "abc"},
        headers={
            "OAuth-Client-Attestation": "attestation",
            "OAuth-Client-Attestation-PoP": "proof",
        },
    )
    extra_ctx = SimpleNamespace(uid="tenant-1", db=object())
    validator = AsyncMock(return_value={"cnf_jkt": "attestation-jkt"})
    monkeypatch.setattr("tenant.oauth.grants.settings.ATTESTATION_ENABLED", enabled)
    monkeypatch.setattr("tenant.oauth.grants.settings.ATTESTATION_REQUIRED", required)
    monkeypatch.setattr("tenant.oauth.grants.get_context", lambda _req: extra_ctx)
    monkeypatch.setattr("tenant.oauth.grants.validate_client_attestation", validator)

    grant = PreAuthorizedCodeGrant(request, server)
    await grant.validate_token_request()

    if expected_required is None:
        validator.assert_not_awaited()
        assert grant._attestation_meta is None
    else:
        assert validator.await_args.kwargs["attestation_required"] is expected_required
        assert grant._attestation_meta == {"cnf_jkt": "attestation-jkt"}


@pytest.mark.asyncio
async def test_provider_lookup_outage_is_not_a_client_error(monkeypatch):
    """A provider lookup outage returns 503, not a 4xx client error."""
    server = DummyServer()
    request = make_request(
        {"pre_authorized_code": "abc"},
        headers={
            "OAuth-Client-Attestation": "attestation",
            "OAuth-Client-Attestation-PoP": "proof",
        },
    )
    extra_ctx = SimpleNamespace(uid="tenant-1", db=object())
    monkeypatch.setattr("tenant.oauth.grants.get_context", lambda _req: extra_ctx)
    monkeypatch.setattr("tenant.oauth.grants.settings.ATTESTATION_ENABLED", True)
    monkeypatch.setattr(
        "tenant.oauth.grants.validate_client_attestation",
        AsyncMock(side_effect=AttestationLookupError("admin unreachable")),
    )

    grant = PreAuthorizedCodeGrant(request, server)
    with pytest.raises(HTTPException) as exc_info:
        await grant.validate_token_request()

    assert exc_info.value.status_code == 503
