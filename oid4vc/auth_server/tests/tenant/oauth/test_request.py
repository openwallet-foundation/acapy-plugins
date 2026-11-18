from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from joserfc import jwk, jwt
from starlette.requests import Request

from core.consts import OAuth2GrantType
from tenant.oauth.integration.request import to_oauth2_request
from tenant.routers import token as token_routes
from tenant.services.attestation_service import InvalidAttestationError, _jwt_extract


def _starlette_request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("as.example.com", 443),
            "path": "/tenants/t1/token",
            "query_string": b"",
            "headers": headers,
        }
    )


@pytest.mark.asyncio
async def test_repeated_headers_are_combined_not_dropped():
    request = _starlette_request(
        [(b"oauth-client-attestation", b"a"), (b"oauth-client-attestation", b"b")]
    )

    oauth2_req = await to_oauth2_request(request)

    assert oauth2_req.headers["oauth-client-attestation"] == "a, b"


@pytest.mark.asyncio
async def test_two_attestation_headers_are_rejected():
    """Client attestation §7.1 requires precisely one attestation header field."""
    key = jwk.ECKey.generate_key("P-256")
    token = jwt.encode({"alg": "ES256", "typ": "oauth-client-attestation+jwt"}, {}, key)
    request = _starlette_request(
        [
            (b"oauth-client-attestation", token.encode()),
            (b"oauth-client-attestation", token.encode()),
        ]
    )

    oauth2_req = await to_oauth2_request(request)

    _jwt_extract(token)
    with pytest.raises(InvalidAttestationError):
        _jwt_extract(oauth2_req.headers["oauth-client-attestation"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("grant_type", "credentials"),
    [
        (OAuth2GrantType.PRE_AUTH_CODE, {"pre-authorized_code": "code"}),
        (OAuth2GrantType.REFRESH_TOKEN, {"refresh_token": "refresh"}),
    ],
)
async def test_token_endpoint_preserves_client_id(monkeypatch, grant_type, credentials):
    server = SimpleNamespace(
        create_token_response_async=AsyncMock(return_value=(200, {}, []))
    )
    monkeypatch.setattr(token_routes, "get_authorization_server", lambda: server)
    app = FastAPI()
    app.include_router(token_routes.router)
    app.dependency_overrides[token_routes.get_db_session] = lambda: object()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://as.example.com"
    ) as client:
        response = await client.post(
            "/tenants/t1/token",
            data={
                "grant_type": grant_type,
                "client_id": "wallet-client",
                **credentials,
            },
        )

    assert response.status_code == 200
    request = server.create_token_response_async.await_args.args[0]
    assert request.payload.data["client_id"] == "wallet-client"
