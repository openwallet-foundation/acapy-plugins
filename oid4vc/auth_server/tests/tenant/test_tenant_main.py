from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import tenant.main as tenant_main


@pytest.mark.asyncio
async def test_health_check_endpoint():
    result = await tenant_main.health_check()
    assert result == {"status": "ok"}


@pytest.mark.asyncio
async def test_tenant_health_check_success(monkeypatch):
    class DummySession(AsyncSession):
        executed = False

        async def execute(self, stmt):
            self.executed = True

        async def close(self):
            pass

    sessions = [DummySession()]
    monkeypatch.setattr(
        tenant_main,
        "get_db_session",
        lambda: (session for session in sessions),
    )

    result = await tenant_main.tenant_health_check(
        "tenant-1", cast(AsyncSession, sessions[0])
    )
    assert result == {"status": "ok", "tenant": "tenant-1"}
