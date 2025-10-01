from datetime import timedelta
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.services import internal_service


class DummyScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class DummyListResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._values))


class DummySession:
    def __init__(self, result):
        self._result = result

    async def execute(self, _stmt):
        return self._result


@pytest.mark.asyncio
async def test_get_tenant_db_returns_urls(monkeypatch):
    tenant_row = SimpleNamespace(uid="tenant-1", active=True)

    monkeypatch.setattr(
        internal_service,
        "resolve_tenant_urls",
        lambda row: ("async-url", "sync-url", "schema"),
    )

    session = cast(AsyncSession, DummySession(DummyScalarResult(tenant_row)))

    result = await internal_service.get_tenant_db(session, "tenant-1")

    assert result == {"db_url": "async-url", "db_schema": "schema"}


@pytest.mark.asyncio
async def test_get_tenant_db_raises_when_missing(monkeypatch):
    session = cast(AsyncSession, DummySession(DummyScalarResult(None)))

    with pytest.raises(HTTPException) as exc_info:
        await internal_service.get_tenant_db(session, "unknown")

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "tenant_not_found_or_inactive"


@pytest.mark.asyncio
async def test_get_tenant_jwks_filters_keys(monkeypatch):
    fixed_now = internal_service.datetime.now(internal_service.timezone.utc)

    valid_row = SimpleNamespace(
        public_jwk={"kty": "OKP"},
        kid="good",
        alg="EdDSA",
        status="active",
        not_before=fixed_now,
        not_after=None,
        updated_at=None,
        created_at=fixed_now,
    )
    grace_row = SimpleNamespace(
        public_jwk={"kty": "EC"},
        kid="grace",
        alg="ES256",
        status="active",
        not_before=fixed_now,
        not_after=fixed_now - timedelta(seconds=10),
        updated_at=None,
        created_at=fixed_now - timedelta(seconds=20),
    )
    retired_row = SimpleNamespace(
        public_jwk={"kty": "EC"},
        kid="retired",
        alg="ES256",
        status="retired",
        not_before=fixed_now - timedelta(minutes=5),
        not_after=None,
        updated_at=fixed_now - timedelta(seconds=10),
        created_at=fixed_now - timedelta(minutes=10),
    )
    revoked_row = SimpleNamespace(
        public_jwk={"kty": "EC"},
        kid="revoked",
        alg="ES256",
        status="revoked",
        not_before=fixed_now,
        not_after=None,
        updated_at=None,
        created_at=fixed_now,
    )

    rows = [valid_row, grace_row, retired_row, revoked_row]

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(internal_service, "datetime", FakeDateTime)
    monkeypatch.setattr(internal_service.settings, "KEY_VERIFY_GRACE_TTL", 60)
    monkeypatch.setattr(
        internal_service, "is_time_valid", lambda row, now: row.kid == "good"
    )

    def _import_key(jwk):
        return SimpleNamespace(as_dict=lambda **kwargs: {**jwk, **kwargs})

    monkeypatch.setattr(internal_service.JsonWebKey, "import_key", _import_key)

    session = cast(AsyncSession, DummySession(DummyListResult(rows)))

    result = await internal_service.get_tenant_jwks(session, "tenant-1")

    kids = {jwk["kid"] for jwk in result["keys"]}
    assert kids == {"good", "grace", "retired"}


@pytest.mark.asyncio
async def test_get_tenant_jwks_empty_when_no_rows(monkeypatch):
    session = cast(AsyncSession, DummySession(DummyListResult([])))

    result = await internal_service.get_tenant_jwks(session, "tenant-1")

    assert result == {"keys": []}
