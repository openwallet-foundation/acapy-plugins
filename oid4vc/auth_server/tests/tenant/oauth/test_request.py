import pytest
from joserfc import jwk, jwt
from starlette.requests import Request

from tenant.oauth.integration.request import to_oauth2_request
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
    """draft-07 §6.2: precisely one OAuth-Client-Attestation header field."""
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
