from types import SimpleNamespace

import pytest

import tenant.services.signing_service as signing_service


class FakeHttpNamespace(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.HTTPStatusError = signing_service.httpx.HTTPStatusError
        self.RequestError = signing_service.httpx.RequestError
        self.Request = signing_service.httpx.Request
        self.Response = signing_service.httpx.Response


@pytest.mark.asyncio
async def test_remote_sign_jwt_success(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            request = signing_service.httpx.Request("POST", url)
            return signing_service.httpx.Response(
                200, json={"jwt": "signed"}, request=request
            )

    monkeypatch.setattr(
        signing_service, "httpx", FakeHttpNamespace(AsyncClient=FakeClient)
    )
    monkeypatch.setattr(
        signing_service.settings, "ADMIN_INTERNAL_BASE_URL", "https://admin"
    )
    monkeypatch.setattr(signing_service.settings, "ADMIN_INTERNAL_AUTH_TOKEN", "token")
    monkeypatch.setattr(signing_service, "current_request_id", lambda: "req-123")

    result = await signing_service.remote_sign_jwt(
        uid="tenant-1", claims={"sub": "abc"}, kid="kid1"
    )

    assert captured["url"] == "https://admin/tenants/tenant-1/jwts"
    assert captured["json"] == {"claims": {"sub": "abc"}, "kid": "kid1"}
    assert captured["headers"] == {
        "Authorization": "Bearer token",
        "X-Request-ID": "req-123",
    }
    assert captured["timeout"] == 10.0
    assert result == {"jwt": "signed"}


@pytest.mark.asyncio
async def test_remote_sign_jwt_without_kid(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *args, **kwargs):
            request = signing_service.httpx.Request("POST", url)
            return signing_service.httpx.Response(
                200, json={"jwt": "signed"}, request=request
            )

    monkeypatch.setattr(
        signing_service, "httpx", FakeHttpNamespace(AsyncClient=FakeClient)
    )
    monkeypatch.setattr(
        signing_service.settings, "ADMIN_INTERNAL_BASE_URL", "https://admin"
    )
    monkeypatch.setattr(signing_service.settings, "ADMIN_INTERNAL_AUTH_TOKEN", "token")
    monkeypatch.setattr(signing_service, "current_request_id", lambda: None)

    result = await signing_service.remote_sign_jwt(uid="tenant-1", claims={"sub": "abc"})

    assert result == {"jwt": "signed"}


@pytest.mark.asyncio
async def test_remote_sign_jwt_raises_on_http_error(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *args, **kwargs):
            request = signing_service.httpx.Request("POST", url)
            return signing_service.httpx.Response(500, request=request)

    monkeypatch.setattr(
        signing_service, "httpx", FakeHttpNamespace(AsyncClient=FakeClient)
    )
    monkeypatch.setattr(
        signing_service.settings, "ADMIN_INTERNAL_BASE_URL", "https://admin"
    )
    monkeypatch.setattr(signing_service.settings, "ADMIN_INTERNAL_AUTH_TOKEN", "token")
    monkeypatch.setattr(signing_service, "current_request_id", lambda: None)

    with pytest.raises(signing_service.httpx.HTTPStatusError):
        await signing_service.remote_sign_jwt(uid="tenant-1", claims={})
