"""Unit tests for WebVHServerClient attested resource upload recovery."""

from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from aiohttp import ClientConnectionError
from acapy_agent.utils.testing import create_test_profile

from ...tests.fixtures import TEST_SERVER_URL
from ..exceptions import OperationError
from ..server_client import WebVHServerClient

TEST_RESOURCE_ID = "did:webvh:QmScid:sandbox.bcvh.vonx.io:test:abc/resources/zQmDigestA"
TEST_RESOURCE = {
    "id": TEST_RESOURCE_ID,
    "content": {"tag": "tag", "credDefId": "cred-def"},
    "metadata": {
        "resourceId": "zQmDigestA",
        "resourceType": "anonCredsSchema",
    },
}
STORED_RESOURCE = {**TEST_RESOURCE, "proof": {"type": "DataIntegrityProof"}}


class _FakeResponse:
    def __init__(self, status, payload=None, content_type="application/json"):
        self.status = status
        self._payload = payload if payload is not None else {}
        self.headers = {"Content-Type": content_type} if content_type else {}

    async def text(self):
        import json

        if isinstance(self._payload, str):
            return self._payload
        return json.dumps(self._payload)

    async def json(self):
        return self._payload

    async def read(self):
        return b""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _RaisingCM:
    def __init__(self, exc):
        self._exc = exc

    async def __aenter__(self):
        raise self._exc

    async def __aexit__(self, exc_type, ext, tb):
        return False


class _FakeSession:
    def __init__(self, handler):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        return self._handler("POST", url, kwargs)

    def put(self, url, **kwargs):
        return self._handler("PUT", url, kwargs)

    def get(self, url, **kwargs):
        return self._handler("GET", url, kwargs)


class TestUploadAttestedResource(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.settings.set_value(
            "plugin_config", {"webvh": {"server_url": TEST_SERVER_URL}}
        )
        self.client = WebVHServerClient(self.profile)
        self.calls = []

    def _patch_session(self, handler):
        return patch(
            "webvh.did.server_client.ClientSession",
            side_effect=lambda *args, **kwargs: _FakeSession(handler),
        )

    async def test_timeout_then_get_200_returns_stored_resource(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _RaisingCM(ClientConnectionError("Connection timeout to host"))
            if method == "GET":
                return _FakeResponse(200, STORED_RESOURCE)
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET"]

    async def test_timeout_then_get_404_replays_post(self):
        posts = {"n": 0}

        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                posts["n"] += 1
                if posts["n"] == 1:
                    return _RaisingCM(ClientConnectionError("Connection timeout to host"))
                return _FakeResponse(201, STORED_RESOURCE)
            if method == "GET":
                return _FakeResponse(404, {"detail": "not found"})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET", "POST"]

    async def test_post_409_already_exists_returns_stored_resource(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _FakeResponse(
                    409, {"detail": "Resource already exists with ID 'zQmDigestA'."}
                )
            if method == "GET":
                return _FakeResponse(200, STORED_RESOURCE)
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET"]

    async def test_post_500_falls_back_to_put(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _FakeResponse(500, {"detail": "internal"})
            if method == "PUT":
                return _FakeResponse(200, STORED_RESOURCE)
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "PUT"]

    async def test_timeout_get_404_replay_fails_raises(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _RaisingCM(ClientConnectionError("Connection timeout to host"))
            if method == "GET":
                return _FakeResponse(404, {"detail": "not found"})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            with self.assertRaises(OperationError):
                await self.client.upload_attested_resource(TEST_RESOURCE)

        assert self.calls[0] == "POST"
        assert "GET" in self.calls

    async def test_timeout_then_empty_get_200_does_not_count_as_success(self):
        posts = {"n": 0}

        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                posts["n"] += 1
                if posts["n"] == 1:
                    return _RaisingCM(ClientConnectionError("Connection timeout to host"))
                return _FakeResponse(201, STORED_RESOURCE)
            if method == "GET":
                return _FakeResponse(200, {})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET", "POST"]

    async def test_timeout_then_wrong_json_get_200_does_not_count_as_success(self):
        posts = {"n": 0}

        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                posts["n"] += 1
                if posts["n"] == 1:
                    return _RaisingCM(ClientConnectionError("Connection timeout to host"))
                return _FakeResponse(201, STORED_RESOURCE)
            if method == "GET":
                return _FakeResponse(200, {"detail": "ok", "id": "not-the-resource"})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET", "POST"]

    async def test_post_409_get_404_raises(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _FakeResponse(
                    409, {"detail": "Resource already exists with ID 'zQmDigestA'."}
                )
            if method == "GET":
                return _FakeResponse(404, {"detail": "not found"})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            with self.assertRaises(OperationError):
                await self.client.upload_attested_resource(TEST_RESOURCE)

        assert self.calls == ["POST", "GET"]

    async def test_post_201_empty_body_succeeds_only_after_get_confirms(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _FakeResponse(201, {})
            if method == "GET":
                return _FakeResponse(200, STORED_RESOURCE)
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            result = await self.client.upload_attested_resource(TEST_RESOURCE)

        assert result == STORED_RESOURCE
        assert self.calls == ["POST", "GET"]

    async def test_post_201_empty_body_get_empty_raises(self):
        def handler(method, url, kwargs):
            self.calls.append(method)
            if method == "POST":
                return _FakeResponse(201, {})
            if method == "GET":
                return _FakeResponse(200, {})
            raise AssertionError(f"unexpected {method} {url}")

        with self._patch_session(handler):
            with self.assertRaises(OperationError):
                await self.client.upload_attested_resource(TEST_RESOURCE)

        assert self.calls == ["POST", "GET"]
