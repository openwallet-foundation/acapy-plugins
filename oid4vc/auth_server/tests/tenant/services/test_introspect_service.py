from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.services import introspect_service


class DummyRepo:
    def __init__(self, token):
        self._token = token

    async def get_by_token(self, token_str):
        assert token_str == "access-token"
        return self._token


class DummySession(AsyncSession):
    def __init__(self):
        pass


@pytest.mark.asyncio
async def test_introspect_returns_active_payload(monkeypatch):
    now = datetime.now(timezone.utc)
    token = SimpleNamespace(
        token="access-token",
        revoked=False,
        expires_at=now + timedelta(minutes=5),
        issued_at=now - timedelta(minutes=1),
        subject=SimpleNamespace(uid="subject-1"),
        token_metadata={
            "realm": "tenant-1",
            "iss": "https://issuer",
            "authorization_details": [{"type": "openid_credential"}],
            "amr": ["dpop"],
            "attestation": {"type": "device"},
            "scope": "openid",
            "c_nonce": "nonce",
            "c_nonce_expires_in": 60,
        },
        cnf_jkt="thumbprint",
    )

    monkeypatch.setattr(
        introspect_service, "AccessTokenRepository", lambda db: DummyRepo(token)
    )
    monkeypatch.setattr(introspect_service, "utcnow", lambda: now)

    resp = await introspect_service.introspect_access_token(
        DummySession(), "tenant-1", "access-token"
    )

    assert resp["active"] is True
    assert resp["sub"] == "subject-1"
    assert resp["token_type"] == "DPoP"
    assert resp["realm"] == "tenant-1"
    assert resp["iss"] == "https://issuer"
    assert resp["authorization_details"] == [{"type": "openid_credential"}]
    assert resp["cnf"] == {"jkt": "thumbprint"}
    assert resp["c_nonce"] == "nonce"
    assert resp["c_nonce_expires_in"] == 60


@pytest.mark.asyncio
async def test_introspect_inactive_for_missing_token(monkeypatch):
    monkeypatch.setattr(
        introspect_service, "AccessTokenRepository", lambda db: DummyRepo(None)
    )

    resp = await introspect_service.introspect_access_token(
        DummySession(), "tenant-1", "access-token"
    )

    assert resp == {"active": False}


@pytest.mark.asyncio
async def test_introspect_inactive_for_wrong_realm(monkeypatch):
    now = datetime.now(timezone.utc)
    token = SimpleNamespace(
        token="access-token",
        revoked=False,
        expires_at=now + timedelta(minutes=5),
        issued_at=now - timedelta(minutes=1),
        subject=SimpleNamespace(uid="subject-1"),
        token_metadata={"realm": "tenant-other"},
        cnf_jkt=None,
    )

    monkeypatch.setattr(
        introspect_service, "AccessTokenRepository", lambda db: DummyRepo(token)
    )
    monkeypatch.setattr(introspect_service, "utcnow", lambda: now)

    resp = await introspect_service.introspect_access_token(
        DummySession(), "tenant-1", "access-token"
    )

    assert resp == {"active": False}


@pytest.mark.asyncio
async def test_introspect_inactive_when_expired(monkeypatch):
    now = datetime.now(timezone.utc)
    token = SimpleNamespace(
        token="access-token",
        revoked=False,
        expires_at=now - timedelta(seconds=1),
        issued_at=now - timedelta(minutes=10),
        subject=SimpleNamespace(uid="subject-1"),
        token_metadata={"realm": "tenant-1"},
        cnf_jkt=None,
    )

    monkeypatch.setattr(
        introspect_service, "AccessTokenRepository", lambda db: DummyRepo(token)
    )
    monkeypatch.setattr(introspect_service, "utcnow", lambda: now)

    resp = await introspect_service.introspect_access_token(
        DummySession(), "tenant-1", "access-token"
    )

    assert resp == {"active": False}
