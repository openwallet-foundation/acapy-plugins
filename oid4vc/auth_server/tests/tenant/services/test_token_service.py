from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.services import token_service


class DummySession(AsyncSession):
    def __init__(self):
        self.committed = False

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_issue_by_pre_auth_code_excludes_realm_from_claims(monkeypatch):
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    access_exp = now + timedelta(minutes=5)
    refresh_exp = now + timedelta(hours=1)

    pac = SimpleNamespace(
        id=1,
        user_pin_required=False,
        user_pin=None,
        subject=SimpleNamespace(uid="sub-123"),
        subject_id=10,
        authorization_details=[{"type": "openid_credential", "format": "mso_mdoc"}],
    )

    created_access_repo: dict[str, object] = {}
    created_refresh_repo: dict[str, object] = {}

    class StubGrantRepo:
        def __init__(self, _db):
            pass

        async def get_by_code(self, code):
            assert code == "code-123"
            return pac

        async def consume_valid(self, pac_id, consumed_at):
            assert pac_id == pac.id
            assert consumed_at is now
            return True

    class StubAccessRepo:
        def __init__(self, _db):
            created_access_repo["instance"] = self
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace(
                id=99,
                subject_id=kwargs["subject_id"],
                token=kwargs["token"],
                issued_at=kwargs["issued_at"],
                expires_at=kwargs["expires_at"],
            )

        async def get_by_id(self, _access_token_id):  # pragma: no cover
            raise AssertionError("unexpected call")

    class StubRefreshRepo:
        def __init__(self, _db):
            created_refresh_repo["instance"] = self
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace()

        async def consume_valid(self, *_args, **_kwargs):  # pragma: no cover
            raise AssertionError("unexpected call")

    monkeypatch.setattr(token_service, "GrantRepository", StubGrantRepo)
    monkeypatch.setattr(token_service, "AccessTokenRepository", StubAccessRepo)
    monkeypatch.setattr(token_service, "RefreshTokenRepository", StubRefreshRepo)
    monkeypatch.setattr(token_service, "utcnow", lambda: now)
    monkeypatch.setattr(token_service, "compute_access_exp", lambda _now: access_exp)
    monkeypatch.setattr(token_service, "compute_refresh_exp", lambda _now: refresh_exp)
    monkeypatch.setattr(token_service, "new_refresh_token", lambda: "refresh-123")
    monkeypatch.setattr(token_service, "hash_token", lambda value: f"hash-{value}")
    monkeypatch.setattr(token_service.settings, "INCLUDE_NONCE", False, raising=False)

    sign_mock = AsyncMock(return_value={"jwt": "signed-token"})
    monkeypatch.setattr(token_service, "remote_sign_jwt", sign_mock)

    db = DummySession()

    (
        access_token,
        refresh_token,
        meta,
    ) = await token_service.TokenService.issue_by_pre_auth_code(
        db=db,
        uid="tenant-1",
        code="code-123",
        realm="tenant-1",
    )

    assert sign_mock.await_count == 1
    await_args = sign_mock.await_args
    assert await_args is not None
    claims = await_args.kwargs["claims"]
    assert "realm" not in claims
    assert "authorization_details" not in claims
    assert claims["iss"].endswith("/tenants/tenant-1")

    assert access_token.token == "signed-token"
    assert refresh_token == "refresh-123"
    assert meta["authorization_details"] == pac.authorization_details

    access_repo = created_access_repo.get("instance")
    assert isinstance(access_repo, StubAccessRepo)
    assert isinstance(access_repo.created_with, dict)
    token_meta = access_repo.created_with.get("token_metadata")
    assert token_meta is not None
    assert token_meta["realm"] == "tenant-1"
    assert token_meta["authorization_details"] == pac.authorization_details

    refresh_repo = created_refresh_repo.get("instance")
    assert isinstance(refresh_repo, StubRefreshRepo)
    assert isinstance(refresh_repo.created_with, dict)
    refresh_meta = refresh_repo.created_with.get("token_metadata")
    assert refresh_meta is not None
    assert refresh_meta["realm"] == "tenant-1"
    assert db.committed is True


@pytest.mark.asyncio
async def test_rotate_by_refresh_token_excludes_realm_from_claims(monkeypatch):
    now = datetime(2025, 2, 2, tzinfo=timezone.utc)
    access_exp = now + timedelta(minutes=10)
    refresh_exp = now + timedelta(days=3)

    prev_access = SimpleNamespace(
        id=77,
        subject=SimpleNamespace(uid="sub-456"),
        token_metadata={"realm": "tenant-2"},
    )

    created_access_repo: dict[str, object] = {}
    created_refresh_repo: dict[str, object] = {}

    class StubAccessRepo:
        def __init__(self, _db):
            created_access_repo["instance"] = self
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace(
                id=88,
                subject_id=kwargs["subject_id"],
                token=kwargs["token"],
                issued_at=kwargs["issued_at"],
                expires_at=kwargs["expires_at"],
            )

        async def get_by_id(self, access_token_id):
            assert access_token_id == prev_access.id
            return prev_access

    class StubRefreshRepo:
        def __init__(self, _db):
            created_refresh_repo["instance"] = self
            self.created_with = None

        async def consume_valid(self, token_hash, now):
            assert token_hash == "hash-existing-refresh"
            assert now is now_ref
            return (55, prev_access.id)

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace()

    now_ref = now

    monkeypatch.setattr(token_service, "AccessTokenRepository", StubAccessRepo)
    monkeypatch.setattr(token_service, "RefreshTokenRepository", StubRefreshRepo)
    monkeypatch.setattr(token_service, "hash_token", lambda value: f"hash-{value}")
    monkeypatch.setattr(token_service, "utcnow", lambda: now)
    monkeypatch.setattr(token_service, "compute_access_exp", lambda _now: access_exp)
    monkeypatch.setattr(token_service, "compute_refresh_exp", lambda _now: refresh_exp)
    monkeypatch.setattr(token_service, "new_refresh_token", lambda: "refresh-new")
    monkeypatch.setattr(token_service.settings, "INCLUDE_NONCE", False, raising=False)

    sign_mock = AsyncMock(return_value={"jwt": "new-signed"})
    monkeypatch.setattr(token_service, "remote_sign_jwt", sign_mock)

    db = DummySession()

    (
        access_token,
        refresh_token,
        meta,
    ) = await token_service.TokenService.rotate_by_refresh_token(
        db=db,
        uid="tenant-2",
        refresh_token_value="existing-refresh",
        realm="tenant-2",
    )

    assert sign_mock.await_count == 1
    await_args = sign_mock.await_args
    assert await_args is not None
    claims = await_args.kwargs["claims"]
    assert "realm" not in claims
    assert claims["sub"] == "sub-456"

    assert access_token.token == "new-signed"
    assert refresh_token == "refresh-new"
    assert meta == {}

    access_repo = created_access_repo.get("instance")
    assert isinstance(access_repo, StubAccessRepo)
    assert isinstance(access_repo.created_with, dict)
    access_meta = access_repo.created_with.get("token_metadata")
    assert access_meta is not None
    assert access_meta["realm"] == "tenant-2"

    refresh_repo = created_refresh_repo.get("instance")
    assert isinstance(refresh_repo, StubRefreshRepo)
    assert isinstance(refresh_repo.created_with, dict)
    refresh_meta = refresh_repo.created_with.get("token_metadata")
    assert refresh_meta is not None
    assert refresh_meta["realm"] == "tenant-2"
    assert db.committed is True


@pytest.mark.asyncio
async def test_issue_by_pre_auth_code_raises_invalid_grant(monkeypatch):
    class StubGrantRepo:
        def __init__(self, _db):
            pass

        async def get_by_code(self, code):
            assert code == "missing"
            return None

        async def consume_valid(self, *_args, **_kwargs):  # pragma: no cover
            raise AssertionError("consume_valid should not be called")

    monkeypatch.setattr(token_service, "GrantRepository", StubGrantRepo)
    monkeypatch.setattr(token_service, "AccessTokenRepository", lambda _db: None)
    monkeypatch.setattr(token_service, "RefreshTokenRepository", lambda _db: None)

    class FailingSession(DummySession):
        async def commit(self):  # pragma: no cover - call is guarded by exception
            raise AssertionError("commit should not be reached")

    with pytest.raises(HTTPException) as exc_info:
        await token_service.TokenService.issue_by_pre_auth_code(
            db=FailingSession(),
            uid="tenant-x",
            code="missing",
            realm="tenant-x",
        )

    assert exc_info.value.detail == "invalid_grant"


@pytest.mark.asyncio
async def test_issue_by_pre_auth_code_includes_nonce_when_enabled(monkeypatch):
    now = datetime(2025, 3, 3, tzinfo=timezone.utc)
    access_exp = now + timedelta(minutes=2)
    refresh_exp = now + timedelta(hours=2)

    pac = SimpleNamespace(
        id=5,
        user_pin_required=False,
        user_pin=None,
        subject=SimpleNamespace(uid="sub-789"),
        subject_id=77,
        authorization_details=None,
    )

    class StubGrantRepo:
        def __init__(self, _db):
            pass

        async def get_by_code(self, code):
            assert code == "code-789"
            return pac

        async def consume_valid(self, pac_id, consumed_at):
            assert pac_id == pac.id
            assert consumed_at is now
            return True

    class StubAccessRepo:
        def __init__(self, _db):
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace(
                id=123,
                subject_id=kwargs["subject_id"],
                token=kwargs["token"],
                issued_at=kwargs["issued_at"],
                expires_at=kwargs["expires_at"],
            )

        async def get_by_id(self, _access_token_id):  # pragma: no cover
            raise AssertionError("unexpected call")

    class StubRefreshRepo:
        def __init__(self, _db):
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace()

        async def consume_valid(self, *_args, **_kwargs):  # pragma: no cover
            raise AssertionError("unexpected call")

    monkeypatch.setattr(token_service, "GrantRepository", StubGrantRepo)
    monkeypatch.setattr(token_service, "AccessTokenRepository", StubAccessRepo)
    monkeypatch.setattr(token_service, "RefreshTokenRepository", StubRefreshRepo)
    monkeypatch.setattr(token_service, "utcnow", lambda: now)
    monkeypatch.setattr(token_service, "compute_access_exp", lambda _now: access_exp)
    monkeypatch.setattr(token_service, "compute_refresh_exp", lambda _now: refresh_exp)
    monkeypatch.setattr(token_service, "new_refresh_token", lambda: "refresh-xyz")
    monkeypatch.setattr(token_service, "hash_token", lambda value: f"hash-{value}")
    monkeypatch.setattr(token_service.settings, "INCLUDE_NONCE", True, raising=False)
    monkeypatch.setattr(token_service.settings, "ACCESS_TOKEN_TTL", 120, raising=False)
    monkeypatch.setattr(token_service.secrets, "token_urlsafe", lambda _: "nonce-xyz")

    sign_mock = AsyncMock(return_value={"jwt": "signed-xyz"})
    monkeypatch.setattr(token_service, "remote_sign_jwt", sign_mock)

    db = DummySession()

    (
        access_token,
        refresh_token,
        meta,
    ) = await token_service.TokenService.issue_by_pre_auth_code(
        db=db,
        uid="tenant-nonce",
        code="code-789",
        realm="tenant-nonce",
    )

    assert meta["c_nonce"] == "nonce-xyz"
    assert meta["c_nonce_expires_in"] == 120
    assert access_token.token == "signed-xyz"
    assert refresh_token == "refresh-xyz"
    assert db.committed is True


@pytest.mark.asyncio
async def test_rotate_by_refresh_token_preserves_authorization_details(monkeypatch):
    now = datetime(2025, 4, 4, tzinfo=timezone.utc)
    access_exp = now + timedelta(minutes=10)
    refresh_exp = now + timedelta(days=1)
    outer_now = now

    auth_details = [{"type": "openid_credential", "format": "jwt_vc"}]
    prev_access = SimpleNamespace(
        id=42,
        subject=SimpleNamespace(uid="sub-rot"),
        token_metadata={"authorization_details": auth_details},
    )

    created_access_repo: dict[str, object] = {}
    created_refresh_repo: dict[str, object] = {}

    class StubAccessRepo:
        def __init__(self, _db):
            created_access_repo["instance"] = self
            self.created_with = None

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace(
                id=500,
                subject_id=kwargs["subject_id"],
                token=kwargs["token"],
                issued_at=kwargs["issued_at"],
                expires_at=kwargs["expires_at"],
            )

        async def get_by_id(self, access_token_id):
            assert access_token_id == prev_access.id
            return prev_access

    class StubRefreshRepo:
        def __init__(self, _db):
            created_refresh_repo["instance"] = self
            self.created_with = None

        async def consume_valid(self, *, token_hash, now):
            assert token_hash == "hash-old-rt"
            assert now is outer_now
            return (77, prev_access.id)

        async def create(self, **kwargs):
            self.created_with = kwargs
            return SimpleNamespace()

    monkeypatch.setattr(token_service, "AccessTokenRepository", StubAccessRepo)
    monkeypatch.setattr(token_service, "RefreshTokenRepository", StubRefreshRepo)
    monkeypatch.setattr(token_service, "hash_token", lambda value: f"hash-{value}")
    monkeypatch.setattr(token_service, "utcnow", lambda: now)
    monkeypatch.setattr(token_service, "compute_access_exp", lambda _now: access_exp)
    monkeypatch.setattr(token_service, "compute_refresh_exp", lambda _now: refresh_exp)
    monkeypatch.setattr(token_service, "new_refresh_token", lambda: "refresh-newer")
    monkeypatch.setattr(token_service.settings, "INCLUDE_NONCE", True, raising=False)
    monkeypatch.setattr(token_service.settings, "ACCESS_TOKEN_TTL", 600, raising=False)
    monkeypatch.setattr(token_service.secrets, "token_urlsafe", lambda _: "nonce-rot")

    sign_mock = AsyncMock(return_value={"jwt": "signed-rot"})
    monkeypatch.setattr(token_service, "remote_sign_jwt", sign_mock)

    db = DummySession()

    (
        access_token,
        refresh_token,
        meta,
    ) = await token_service.TokenService.rotate_by_refresh_token(
        db=db,
        uid="tenant-rot",
        refresh_token_value="old-rt",
        realm="tenant-rot",
    )

    assert sign_mock.await_count == 1
    await_args = sign_mock.await_args
    assert await_args is not None
    claims = await_args.kwargs["claims"]
    assert "authorization_details" not in claims
    assert meta["authorization_details"] == auth_details
    assert meta["c_nonce"] == "nonce-rot"
    assert meta["c_nonce_expires_in"] == 600
    assert access_token.token == "signed-rot"
    assert refresh_token == "refresh-newer"
    assert db.committed is True

    access_repo_instance = created_access_repo.get("instance")
    assert isinstance(access_repo_instance, StubAccessRepo)
    assert isinstance(access_repo_instance.created_with, dict)
    access_meta = access_repo_instance.created_with.get("token_metadata")
    assert access_meta is not None
    assert access_meta["authorization_details"] == auth_details

    refresh_repo_instance = created_refresh_repo.get("instance")
    assert isinstance(refresh_repo_instance, StubRefreshRepo)
    assert isinstance(refresh_repo_instance.created_with, dict)
    refresh_meta = refresh_repo_instance.created_with.get("token_metadata")
    assert refresh_meta is not None
    assert refresh_meta["realm"] == "tenant-rot"
