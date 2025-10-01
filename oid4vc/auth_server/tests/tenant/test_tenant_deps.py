from typing import cast

import httpx
import pytest
from fastapi import HTTPException

import tenant.deps as deps


def make_response(
    json_data=None, status_code=200, url="https://admin/tenants/tenant-1/db"
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code, request=httpx.Request("GET", url), json=json_data
    )


class DummyClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
        self.calls.append((url, headers))
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


@pytest.mark.asyncio
async def test_fetch_tenant_ctx_success(monkeypatch):
    deps._CACHE.clear()
    responses = [
        make_response(
            {"db_url": "db://url", "db_schema": "schema"},
            url="https://admin/tenants/tenant-1/db",
        ),
        make_response({"keys": []}, url="https://admin/tenants/tenant-1/jwks"),
    ]

    monkeypatch.setattr(
        deps.httpx, "AsyncClient", lambda **kwargs: DummyClient(responses.copy())
    )

    ctx = await deps._fetch_tenant_ctx("tenant-1")

    assert ctx["db"] == {"url": "db://url", "schema": "schema"}
    assert ctx["jwks"] == {"keys": []}
    assert "tenant-1" in deps._CACHE


@pytest.mark.asyncio
async def test_fetch_tenant_ctx_handles_jwks_error(monkeypatch):
    deps._CACHE.clear()
    responses = [
        make_response(
            {"db_url": "db://url", "db_schema": "schema"},
            url="https://admin/tenants/tenant-1/db",
        ),
        httpx.RequestError(
            "boom", request=httpx.Request("GET", "https://admin/tenants/tenant-1/jwks")
        ),
    ]

    monkeypatch.setattr(
        deps.httpx, "AsyncClient", lambda **kwargs: DummyClient(responses.copy())
    )

    ctx = await deps._fetch_tenant_ctx("tenant-1")

    assert ctx["jwks"] == {"keys": []}


@pytest.mark.asyncio
async def test_fetch_tenant_ctx_db_error(monkeypatch):
    deps._CACHE.clear()
    responses = [
        httpx.HTTPStatusError(
            "server",
            request=httpx.Request("GET", "url"),
            response=make_response({}, status_code=500, url="url"),
        )
    ]

    monkeypatch.setattr(
        deps.httpx, "AsyncClient", lambda **kwargs: DummyClient(responses.copy())
    )

    with pytest.raises(HTTPException) as exc_info:
        await deps._fetch_tenant_ctx("tenant-1")

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_get_tenant_ctx_uses_cache():
    deps._CACHE.clear()
    deps._CACHE["tenant-1"] = (
        deps.time.time(),
        {"db": {"url": "db://cached", "schema": "schema"}},
    )
    section = await deps.get_tenant_ctx("tenant-1", "db")
    assert section["url"] == "db://cached"


@pytest.mark.asyncio
async def test_get_db_session_refreshes_on_failure(monkeypatch):
    deps._CACHE.clear()
    deps._CACHE["tenant-1"] = (
        deps.time.time(),
        {"db": {"url": "db://url", "schema": "schema"}},
    )

    class FakeSession:
        def __init__(self, should_fail=True):
            self.should_fail = should_fail
            self.closed = False
            self.executed = 0

        async def execute(self, stmt):
            self.executed += 1
            if self.should_fail:
                raise RuntimeError("fail")

        async def close(self):
            self.closed = True

    sessions = [FakeSession(True), FakeSession(False)]

    def fake_sessionmaker(url, schema):
        return lambda: sessions.pop(0)

    async def fake_fetch_ctx(uid):
        return {"db": {"url": "db://url2", "schema": "schema2"}}

    monkeypatch.setattr(deps, "_fetch_tenant_ctx", fake_fetch_ctx)
    monkeypatch.setattr(deps, "_sessionmaker_for", fake_sessionmaker)

    class DummyRequest:
        def __init__(self):
            self.path_params = {"uid": "tenant-1"}

    request = DummyRequest()
    ctx = await deps._load_tenant_ctx(cast(deps.Request, request), force=False)

    async def consume():
        async for session in deps.get_db_session(cast(deps.Request, request), ctx):
            assert isinstance(session, FakeSession)
            assert session.executed == 1

    await consume()
