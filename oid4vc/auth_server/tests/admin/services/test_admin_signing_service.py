from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.schemas.internal import JwtSignRequest
from admin.services import signing_service


class DummyScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


class DummySession(AsyncSession):
    def __init__(self, rows):
        super().__init__()  # type: ignore[misc]
        self._rows = rows

    async def execute(self, _stmt):
        return DummyScalarResult(self._rows)


def make_key(**kwargs):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        tenant_id=1,
        kid=kwargs.get("kid", "kid-1"),
        alg=kwargs.get("alg", "ES256"),
        status=kwargs.get("status", "active"),
        public_jwk={"kty": "OKP"},
        private_pem_enc=kwargs.get("private_pem_enc", "encrypted-pem"),
        not_before=kwargs.get("not_before", now - timedelta(minutes=1)),
        not_after=kwargs.get("not_after"),
        created_at=kwargs.get("created_at", now - timedelta(minutes=5)),
        updated_at=kwargs.get("updated_at"),
    )


@pytest.mark.asyncio
async def test_sign_tenant_jwt_success(monkeypatch):
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(
        signing_service, "datetime", SimpleNamespace(now=lambda tz=None: now)
    )
    monkeypatch.setattr(signing_service, "decrypt_private_pem", lambda pem: "private-key")
    monkeypatch.setattr(signing_service.JsonWebKey, "import_key", lambda pem: "jwk")

    class FakeJwt:
        @staticmethod
        def encode(header, claims, jwk):
            return "token".encode()

    monkeypatch.setattr(signing_service, "jwt", FakeJwt)

    key = make_key(private_pem_enc="enc", not_after=now + timedelta(minutes=10))
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: key
    )

    session = DummySession([key])
    req = JwtSignRequest(
        claims={"exp": int((now + timedelta(minutes=5)).timestamp())}, kid=None, alg=None
    )

    resp = await signing_service.sign_tenant_jwt(session, "tenant-1", req)

    assert resp.jwt == "token"
    assert resp.kid == key.kid
    assert resp.alg == key.alg


@pytest.mark.asyncio
async def test_sign_tenant_jwt_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: None
    )
    session = DummySession([])
    req = JwtSignRequest(
        claims={"exp": int(datetime.now(timezone.utc).timestamp()) + 10},
        kid=None,
        alg=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)

    assert exc_info.value.detail == "signing_key_not_found"


@pytest.mark.asyncio
async def test_sign_tenant_jwt_enforces_exp(monkeypatch):
    now = datetime.now(timezone.utc)
    key = make_key()
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: key
    )
    session = DummySession([key])

    # Missing exp
    req = JwtSignRequest(claims={}, kid=None, alg=None)
    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)
    assert exc_info.value.detail == "claims_missing_or_invalid_exp"

    # Exp in past
    req = JwtSignRequest(
        claims={"exp": int((now - timedelta(seconds=1)).timestamp())}, kid=None, alg=None
    )
    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)
    assert exc_info.value.detail == "exp_in_past"

    # Exp beyond max TTL
    future = int(
        (now + timedelta(seconds=signing_service.MAX_TTL_SECONDS + 1)).timestamp()
    )
    req = JwtSignRequest(claims={"exp": future}, kid=None, alg=None)
    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)
    assert exc_info.value.detail == "exp_exceeds_max_ttl"

    # Exp beyond key validity
    key2 = make_key(not_after=now + timedelta(seconds=30))
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: key2
    )
    sess2 = DummySession([key2])
    req = JwtSignRequest(
        claims={"exp": int((now + timedelta(minutes=10)).timestamp())}, kid=None, alg=None
    )
    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(sess2, "tenant-1", req)
    assert exc_info.value.detail == "exp_exceeds_key_validity"


@pytest.mark.asyncio
async def test_sign_tenant_jwt_rejects_wrong_alg(monkeypatch):
    key = make_key(alg="HS256")
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: key
    )
    session = DummySession([key])
    req = JwtSignRequest(
        claims={"exp": int(datetime.now(timezone.utc).timestamp()) + 60},
        kid=None,
        alg=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)

    assert exc_info.value.detail == "unsupported_alg"


@pytest.mark.asyncio
async def test_sign_tenant_jwt_rejects_ttl(monkeypatch):
    key = make_key()
    monkeypatch.setattr(
        signing_service, "select_signing_key", lambda rows, preferred_kid, now: key
    )
    session = DummySession([key])
    req = JwtSignRequest(claims={}, kid=None, alg=None, ttl_seconds=60)

    with pytest.raises(HTTPException) as exc_info:
        await signing_service.sign_tenant_jwt(session, "tenant-1", req)

    assert exc_info.value.detail == "use_exp_not_ttl"
