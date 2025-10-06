import json
from contextlib import asynccontextmanager

import pytest
from fastapi import Request

import admin.main as admin_main


@pytest.mark.asyncio
async def test_health_check_success(monkeypatch):
    class FakeSession:
        def __init__(self):
            self.executed = False

        async def execute(self, stmt):
            self.executed = True

        async def close(self):
            pass

    class FakeManager:
        def __init__(self, session):
            self.session_obj = session
            self.calls = 0

        @asynccontextmanager
        async def session(self):
            self.calls += 1
            yield self.session_obj

    session = FakeSession()
    manager = FakeManager(session)
    monkeypatch.setattr(admin_main, "db_manager", manager)

    response = await admin_main.health_check()
    assert response.status_code == 200
    assert json.loads(response.body) == {"status": "ok"}
    assert session.executed is True
    assert manager.calls == 1


@pytest.mark.asyncio
async def test_health_check_failure(monkeypatch):
    class FailingSession:
        async def execute(self, stmt):
            raise RuntimeError("db down")

        async def close(self):
            pass

    class FakeManager:
        @asynccontextmanager
        async def session(self):
            yield FailingSession()

    monkeypatch.setattr(admin_main, "db_manager", FakeManager())

    response = await admin_main.health_check()
    assert response.status_code == 500
    assert b"database_unavailable" in response.body


@pytest.mark.asyncio
async def test_log_unhandled_exception(monkeypatch):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/test",
        "headers": [],
        "path_params": {},
    }
    request = Request(scope)
    response = await admin_main.log_unhandled_exception(request, Exception("boom"))
    assert response.status_code == 500
    assert response.body == b'{"detail":"Internal Server Error"}'
