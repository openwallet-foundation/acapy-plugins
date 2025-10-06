from contextlib import asynccontextmanager
from typing import AsyncIterator

import pytest

import admin.deps as admin_deps
from core.db.session import DatabaseSessionManager, make_session_dependency


def test_db_manager_search_path():
    assert getattr(admin_deps.db_manager, "_search_path", None) == "admin"


@pytest.mark.asyncio
async def test_get_db_session_uses_manager(monkeypatch):
    class FakeSession:
        def __init__(self):
            self.closed = False

        async def execute(self, _stmt):
            pass

        async def close(self):
            self.closed = True

    class FakeManager(DatabaseSessionManager):
        def __init__(self):
            super().__init__()
            self.calls = 0
            self.session_obj = FakeSession()

        @asynccontextmanager
        async def session(self) -> AsyncIterator[FakeSession]:  # type: ignore[override]
            self.calls += 1
            try:
                yield self.session_obj
            finally:
                await self.session_obj.close()

    fake_manager = FakeManager()
    dep = make_session_dependency(fake_manager)

    monkeypatch.setattr(admin_deps, "db_manager", fake_manager)
    monkeypatch.setattr(admin_deps, "get_db_session", dep)

    async for session in admin_deps.get_db_session():
        assert session is fake_manager.session_obj
    assert fake_manager.calls == 1
    assert fake_manager.session_obj.closed is True
