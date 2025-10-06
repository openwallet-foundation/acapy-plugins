from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

import tenant.services.grant_service as grant_service


class DummySession(AsyncSession):
    def __init__(self):
        super().__init__()  # type: ignore[misc]
        self.committed = False
        self.refreshed: Any = None

    async def commit(self):
        self.committed = True

    async def refresh(self, obj):
        self.refreshed = obj


@pytest.mark.asyncio
async def test_ensure_subject_returns_existing(monkeypatch):
    class StubRepo:
        def __init__(self, db):
            self.db = db

        async def get_id_by_uid(self, uid: str) -> int | None:
            assert uid == "subject-123"
            return 42

    session = DummySession()
    monkeypatch.setattr(grant_service, "SubjectRepository", StubRepo)

    result = await grant_service.ensure_subject(session, "subject-123", None)

    assert result == 42


@pytest.mark.asyncio
async def test_ensure_subject_creates_new_when_missing(monkeypatch):
    calls = {"created_uid": None, "metadata": []}

    class StubRepo:
        def __init__(self, db):
            self.db = db
            self.created = False

        async def get_id_by_uid(self, uid: str) -> int | None:
            return None

        async def create(self, uid: str, metadata: dict | None = None):
            calls["metadata"].append(metadata or {})
            self.created = True
            calls["created_uid"] = uid
            return SimpleNamespace(id=7)

    session = DummySession()
    monkeypatch.setattr(grant_service, "SubjectRepository", StubRepo)
    monkeypatch.setattr(grant_service.uuid, "uuid4", lambda: "generated-uid")

    result = await grant_service.ensure_subject(session, None, {"foo": "bar"})

    assert result == 7
    assert calls["created_uid"] == "generated-uid"
    assert calls["metadata"] == [{"foo": "bar"}]


@pytest.mark.asyncio
async def test_ensure_subject_handles_integrity_error(monkeypatch):
    class StubRepo:
        def __init__(self, db):
            self.db = db
            self.created = False

        async def get_id_by_uid(self, uid: str) -> int | None:
            if uid == "existing-uid":
                return 99
            return None

        async def create(self, uid: str, metadata: dict | None = None):
            raise IntegrityError("err", params=None, orig=None)

    session = DummySession()
    monkeypatch.setattr(grant_service, "SubjectRepository", StubRepo)

    result = await grant_service.ensure_subject(session, "existing-uid", None)

    assert result == 99


@pytest.mark.asyncio
async def test_create_pre_authorized_code_success(monkeypatch):
    session = DummySession()
    capture = {}

    async def fake_ensure_subject(db, subject_id, metadata):
        capture["ensure_args"] = (db, subject_id, metadata)
        return 11

    def fake_new_code() -> str:
        return "code-xyz"

    fixed_now = datetime(2025, 1, 1, tzinfo=timezone.utc)

    class StubGrantRepo:
        def __init__(self, db):
            self.db = db

        async def create_pre_auth_code(self, **kwargs):
            capture["repo_kwargs"] = kwargs
            return SimpleNamespace(id=5)

    class AuthDetails:
        def __init__(self, data):
            self._data = data

        def model_dump(self):
            return self._data

    monkeypatch.setattr(grant_service, "ensure_subject", fake_ensure_subject)
    monkeypatch.setattr(grant_service, "new_code", fake_new_code)
    monkeypatch.setattr(grant_service, "utcnow", lambda: fixed_now)
    monkeypatch.setattr(grant_service, "GrantRepository", StubGrantRepo)
    monkeypatch.setattr(grant_service.settings, "PRE_AUTH_CODE_TTL", 120)

    auth_details = [AuthDetails({"type": "openid_credential"})]

    pac = await grant_service.create_pre_authorized_code(
        db=session,
        subject_id=None,
        subject_metadata={"extra": True},
        user_pin_required=True,
        user_pin="1234",
        authorization_details=auth_details,
        ttl_seconds=None,
    )

    assert pac.id == 5
    assert session.committed is True
    assert session.refreshed == pac

    repo_kwargs = capture["repo_kwargs"]
    assert repo_kwargs["subject_id"] == 11
    assert repo_kwargs["code"] == "code-xyz"
    assert repo_kwargs["user_pin"] == "1234"
    assert repo_kwargs["user_pin_required"] is True
    assert repo_kwargs["authorization_details"] == [{"type": "openid_credential"}]
    assert repo_kwargs["issued_at"] == fixed_now
    assert repo_kwargs["expires_at"] == fixed_now + timedelta(seconds=120)
