import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasicCredentials
from joserfc.jwk import ECKey, KeySet
from starlette.requests import Request

from core.consts import ClientAuthMethod
from tenant.security import client_auth


def make_request() -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/token",
        "root_path": "",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1234),
        "headers": [(b"host", b"testserver")],
        "query_string": b"",
        "app": {},
    }
    return Request(scope)


@pytest.fixture
def stub_client_repo(monkeypatch):
    def _apply(resolver):
        class StubRepository:
            def __init__(self, session):
                self.session = session

            async def get_by_client_id(self, client_id: str):
                return resolver(client_id)

        monkeypatch.setattr(client_auth, "ClientRepository", StubRepository)

    return _apply


def fake_client(**attrs) -> client_auth.AuthClient:
    """Build a lightweight client-compatible object for type checking."""
    return cast(client_auth.AuthClient, SimpleNamespace(**attrs))


# Generate a real EC key for tests that need valid JWKS
_test_key = ECKey.generate_key("P-256", auto_kid=True)
_test_jwks = {"keys": [_test_key.as_dict(private=False)]}


@pytest.mark.asyncio
async def test_load_jwks_from_dict():
    client = fake_client(jwks=_test_jwks, jwks_uri=None)

    result = await client_auth._load_jwks(client)

    assert isinstance(result, KeySet)
    assert len(result.keys) == 1


@pytest.mark.asyncio
async def test_load_jwks_from_json_string():
    client = fake_client(jwks=json.dumps(_test_jwks), jwks_uri=None)

    result = await client_auth._load_jwks(client)

    assert isinstance(result, KeySet)
    assert len(result.keys) == 1


@pytest.mark.asyncio
async def test_load_jwks_invalid_string_returns_none():
    client = fake_client(jwks="not-json", jwks_uri=None)

    result = await client_auth._load_jwks(client)

    assert result is None


@pytest.mark.asyncio
async def test_load_jwks_from_uri(monkeypatch):
    fake_keyset = KeySet.import_key_set(_test_jwks)
    monkeypatch.setattr(
        client_auth,
        "_jwks_uri_cache",
        MagicMock(get_jwks=AsyncMock(return_value=fake_keyset)),
    )

    client = fake_client(jwks=None, jwks_uri="https://example.org/jwks.json")

    result = await client_auth._load_jwks(client)

    assert isinstance(result, KeySet)
    assert len(result.keys) == 1


@pytest.mark.asyncio
async def test_load_jwks_uri_failure_returns_none(monkeypatch):
    monkeypatch.setattr(
        client_auth,
        "_jwks_uri_cache",
        MagicMock(get_jwks=AsyncMock(return_value=None)),
    )
    client = fake_client(jwks=None, jwks_uri="https://bad.example.org")

    result = await client_auth._load_jwks(client)

    assert result is None


def test_validate_jwt_alg_success(monkeypatch):
    monkeypatch.setattr(client_auth, "jwt_header_unverified", lambda _: {"alg": "RS256"})

    client_auth._validate_jwt_alg("token", "RS256")


def test_validate_jwt_alg_failure(monkeypatch):
    monkeypatch.setattr(client_auth, "jwt_header_unverified", lambda _: {"alg": "HS256"})

    with pytest.raises(HTTPException) as exc_info:
        client_auth._validate_jwt_alg("token", "RS256")

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_alg"


def test_validate_jwt_claims_success():
    request = make_request()
    claims = {
        "iss": "issuer",
        "sub": "subject",
        "aud": str(request.url),
        "exp": 123,
        "iat": 100,
        "jti": "unique-id-1",
    }

    client_auth._validate_jwt_claims(claims, request)


def test_validate_jwt_claims_missing():
    request = make_request()

    with pytest.raises(HTTPException) as exc_info:
        client_auth._validate_jwt_claims({}, request)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "missing_iss"


def test_validate_jwt_claims_invalid_audience():
    request = make_request()
    claims = {
        "iss": "issuer",
        "sub": "subject",
        "aud": ["https://other"],
        "exp": 123,
        "iat": 100,
        "jti": "unique-id-2",
    }

    with pytest.raises(HTTPException) as exc_info:
        client_auth._validate_jwt_claims(claims, request)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_audience"


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_success(monkeypatch):
    request = make_request()

    payload = {
        "iss": "issuer",
        "sub": "subject",
        "aud": str(request.url),
        "exp": 123,
        "iat": 100,
        "jti": "unique-id-3",
    }

    class FakeToken:
        claims = payload

    jwt_decode_mock = MagicMock(return_value=FakeToken())
    monkeypatch.setattr(client_auth.jwt, "decode", jwt_decode_mock)
    monkeypatch.setattr(client_auth, "_validate_jwt_alg", lambda *_: None)

    # Also mock JWTClaimsRegistry to avoid real validation
    fake_registry = MagicMock()
    fake_registry.validate = MagicMock()
    monkeypatch.setattr(
        client_auth.jwt, "JWTClaimsRegistry", MagicMock(return_value=fake_registry)
    )
    monkeypatch.setattr(
        client_auth,
        "_pkjwt_jti_cache",
        MagicMock(check_and_store=AsyncMock(return_value=True)),
    )

    claims = await client_auth._decode_and_validate_jwt(
        token="token",
        key_material="secret",
        request=request,
        db=AsyncMock(),
        expected_alg="RS256",
    )

    assert claims == payload
    jwt_decode_mock.assert_called_once_with("token", "secret", algorithms=["RS256"])


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_decode_failure(monkeypatch):
    request = make_request()

    def raise_error(*_args, **_kwargs):
        raise ValueError("bad token")

    monkeypatch.setattr(client_auth.jwt, "decode", raise_error)
    monkeypatch.setattr(client_auth, "jwt_header_unverified", lambda _: {"alg": "ES256"})

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._decode_and_validate_jwt(
            "token", "secret", request, db=AsyncMock()
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_decode_and_validate_jwt_non_mapping(monkeypatch):
    request = make_request()

    class Dummy:
        claims = "not-a-mapping"

    fake_registry = MagicMock()
    fake_registry.validate = MagicMock()
    monkeypatch.setattr(
        client_auth.jwt, "JWTClaimsRegistry", MagicMock(return_value=fake_registry)
    )
    monkeypatch.setattr(client_auth.jwt, "decode", lambda *_args, **_kwargs: Dummy())
    monkeypatch.setattr(client_auth, "_validate_jwt_claims", lambda *_: None)
    monkeypatch.setattr(client_auth, "jwt_header_unverified", lambda _: {"alg": "ES256"})

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._decode_and_validate_jwt(
            "token", "secret", request, db=AsyncMock()
        )

    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_authenticate_private_key_jwt_success(monkeypatch):
    fake_keyset = KeySet.import_key_set(_test_jwks)
    client = fake_client(
        client_auth_signing_alg="RS256",
        client_id="client-1",
        jwks=_test_jwks,
        jwks_uri=None,
        client_secret=None,
    )

    monkeypatch.setattr(client_auth, "_load_jwks", AsyncMock(return_value=fake_keyset))
    decode_mock = AsyncMock(return_value={"sub": "client-1", "iss": "client-1"})
    monkeypatch.setattr(client_auth, "_decode_and_validate_jwt", decode_mock)

    result = await client_auth._authenticate_private_key_jwt(
        client, "token", make_request(), db=AsyncMock()
    )

    assert result == {"sub": "client-1", "iss": "client-1"}
    decode_mock.assert_called_once()


@pytest.mark.asyncio
async def test_authenticate_private_key_jwt_missing_keys(monkeypatch):
    client = fake_client(jwks=None, jwks_uri=None, client_secret=None, client_id="c1")
    monkeypatch.setattr(client_auth, "_load_jwks", AsyncMock(return_value=None))

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._authenticate_private_key_jwt(
            client, "token", make_request(), db=AsyncMock()
        )

    assert exc_info.value.detail == "invalid_client"


def test_authenticate_client_secret_basic_success(monkeypatch):
    client = fake_client(client_secret="stored-hash")
    monkeypatch.setattr(client_auth, "verify_secret_pbkdf2", lambda _token, _stored: True)

    client_auth._authenticate_client_secret_basic(client, "provided")


def test_authenticate_client_secret_basic_failure(monkeypatch):
    client = fake_client(client_secret="stored-hash")
    monkeypatch.setattr(
        client_auth, "verify_secret_pbkdf2", lambda _token, _stored: False
    )

    with pytest.raises(HTTPException) as exc_info:
        client_auth._authenticate_client_secret_basic(client, "provided")

    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_base_client_auth_private_key_jwt_success(monkeypatch, stub_client_repo):
    request = make_request()
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token-123")
    client = fake_client(
        client_id="client-1",
        client_auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
        client_auth_signing_alg="RS256",
        client_secret=None,
        jwks={"keys": []},
        jwks_uri=None,
    )

    stub_client_repo(lambda _: client)
    monkeypatch.setattr(
        client_auth, "jwt_payload_unverified", lambda _: {"sub": "client-1"}
    )
    private_key_mock = AsyncMock(return_value={})
    monkeypatch.setattr(client_auth, "_authenticate_private_key_jwt", private_key_mock)

    result = await client_auth._base_client_auth(
        db=AsyncMock(),
        request=request,
        credentials=credentials,
    )

    assert result is client
    assert request.state.client_id == "client-1"
    private_key_mock.assert_awaited_once()
    called_client, called_token, called_request, called_db = (
        private_key_mock.await_args.args
    )
    assert called_client is client
    assert called_token == "token-123"
    assert called_request is request


@pytest.mark.asyncio
async def test_base_client_auth_client_secret_basic_success(
    monkeypatch, stub_client_repo
):
    request = make_request()
    basic_creds = HTTPBasicCredentials(username="client-1", password="clear-secret")
    client = fake_client(
        client_id="client-1",
        client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        client_auth_signing_alg=None,
        client_secret="stored-hash",
        jwks=None,
        jwks_uri=None,
    )

    stub_client_repo(lambda cid: client if cid == "client-1" else None)
    monkeypatch.setattr(
        client_auth, "verify_secret_pbkdf2", lambda token, stored: token == "clear-secret"
    )

    result = await client_auth._base_client_auth(
        db=AsyncMock(),
        request=request,
        basic_creds=basic_creds,
    )

    assert result is client
    assert request.state.client_id == "client-1"


@pytest.mark.asyncio
async def test_base_client_auth_client_secret_basic_invalid_secret(
    monkeypatch, stub_client_repo
):
    request = make_request()
    basic_creds = HTTPBasicCredentials(username="client-1", password="wrong-secret")
    client = fake_client(
        client_id="client-1",
        client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        client_auth_signing_alg=None,
        client_secret="stored-hash",
        jwks=None,
        jwks_uri=None,
    )

    stub_client_repo(lambda cid: client if cid == "client-1" else None)
    monkeypatch.setattr(client_auth, "verify_secret_pbkdf2", lambda token, stored: False)

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._base_client_auth(
            db=AsyncMock(),
            request=request,
            basic_creds=basic_creds,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_base_client_auth_missing_credentials():
    request = make_request()

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._base_client_auth(db=AsyncMock(), request=request)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "unauthorized"


@pytest.mark.asyncio
async def test_base_client_auth_scheme_not_allowed(monkeypatch, stub_client_repo):
    request = make_request()
    basic_creds = HTTPBasicCredentials(username="client-1", password="value")
    client = fake_client(
        client_id="client-1",
        client_auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
        client_auth_signing_alg="RS256",
        client_secret=None,
        jwks={"keys": []},
        jwks_uri=None,
    )

    stub_client_repo(lambda cid: client if cid == "client-1" else None)

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._base_client_auth(
            db=AsyncMock(),
            request=request,
            basic_creds=basic_creds,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_client"


@pytest.mark.asyncio
async def test_base_client_auth_unknown_client(monkeypatch, stub_client_repo):
    request = make_request()
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token-123")

    stub_client_repo(lambda cid: None)
    monkeypatch.setattr(
        client_auth, "jwt_payload_unverified", lambda _: {"sub": "missing-client"}
    )

    with pytest.raises(HTTPException) as exc_info:
        await client_auth._base_client_auth(
            db=AsyncMock(),
            request=request,
            credentials=credentials,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_client"
