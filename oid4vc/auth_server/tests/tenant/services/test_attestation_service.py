import base64
import json

import pytest

from tenant.services import attestation_service


def _b64(data: dict) -> str:
    encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


def _jwt(payload: dict, header: dict | None = None) -> str:
    header = header or {"alg": "none", "typ": "JWT"}
    return f"{_b64(header)}.{_b64(payload)}.signature"


@pytest.fixture
def default_attestation_settings(monkeypatch):
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_TRUST_POLICY",
        "auto_trust",
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_ALLOW_LIST",
        [],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_DENY_LIST",
        [],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_BIND_DPOP_JKT",
        False,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_CLOCK_SKEW_SECONDS",
        60,
        raising=False,
    )
    # Bypass signature verification for tests focused on policy/claim logic.
    # Dedicated tests for _verify_attestation_signature cover the cryptographic path.
    monkeypatch.setattr(
        attestation_service,
        "_verify_attestation_signature",
        lambda token: attestation_service._jwt_part(token, 1),
    )


def test_validate_client_attestation_optional_missing_returns_none(
    default_attestation_settings,
):
    result = attestation_service.validate_client_attestation(
        client_attestation=None,
        dpop_proof=None,
        attestation_required=False,
    )

    assert result is None


def test_validate_client_attestation_required_missing_raises(
    default_attestation_settings,
):
    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        attestation_service.validate_client_attestation(
            client_attestation=None,
            dpop_proof=None,
            attestation_required=True,
        )

    assert exc_info.value.error == "invalid_attestation"


def test_validate_client_attestation_auto_trust_success(
    monkeypatch,
    default_attestation_settings,
):
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)

    token = _jwt(
        {
            "iss": "https://wallet.example",
            "sub": "wallet-app-1",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
            "cnf": {"jkt": "att-jkt"},
        }
    )

    result = attestation_service.validate_client_attestation(
        client_attestation=token,
        dpop_proof=None,
        attestation_required=True,
    )

    assert isinstance(result, dict)
    assert result["sub"] == "wallet-app-1"
    assert result["policy"] == "auto_trust"
    assert result["decision"] == "trusted"
    assert result["jkt"] == "att-jkt"
    assert result["hash"].startswith("sha256:")


def test_validate_client_attestation_allow_list_blocks_unlisted(
    monkeypatch,
    default_attestation_settings,
):
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_TRUST_POLICY",
        "allow_list",
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_ALLOW_LIST",
        ["wallet-app-allowed"],
        raising=False,
    )

    token = _jwt(
        {
            "iss": "https://wallet.example",
            "sub": "wallet-app-blocked",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        }
    )

    with pytest.raises(attestation_service.AttestationPolicyError) as exc_info:
        attestation_service.validate_client_attestation(
            client_attestation=token,
            dpop_proof=None,
            attestation_required=True,
        )

    assert exc_info.value.error == "invalid_request"


def test_validate_client_attestation_binds_to_dpop_jkt(
    monkeypatch,
    default_attestation_settings,
):
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_BIND_DPOP_JKT",
        True,
        raising=False,
    )

    dpop_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF4dB-MV2rS8d6LaA4NU8TQ4NUnxE27XGr0",
        "y": "x_FEzRu9j9QJ8fW2V7lidhraNROm4tW7x1YgnPZXoqw",
    }
    dpop_jkt = attestation_service._thumbprint_b64url(dpop_jwk)
    dpop = _jwt(
        payload={"htu": "https://auth.example/token", "htm": "POST", "iat": 123},
        header={"alg": "ES256", "typ": "dpop+jwt", "jwk": dpop_jwk},
    )

    token = _jwt(
        {
            "iss": "https://wallet.example",
            "sub": "wallet-app-1",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
            "cnf": {"jkt": dpop_jkt},
        }
    )

    result = attestation_service.validate_client_attestation(
        client_attestation=token,
        dpop_proof=dpop,
        attestation_required=True,
    )

    assert isinstance(result, dict)
    assert result["jkt"] == dpop_jkt


# ---------------------------------------------------------------------------
# _verify_attestation_signature — cryptographic path
# ---------------------------------------------------------------------------


def test_verify_attestation_signature_valid():
    """A properly signed EC JWT passes signature verification."""
    from authlib.jose import JsonWebKey
    from authlib.jose import jwt as jose_jwt

    key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    public_jwk = key.as_dict(is_private=False)
    header = {"alg": "ES256", "typ": "JWT", "jwk": public_jwk}
    payload = {
        "iss": "https://wallet.example",
        "sub": "wallet-1",
        "iat": 1_700_000_000,
        "exp": 9_999_999_999,
    }
    token = jose_jwt.encode(header, payload, key).decode()

    result = attestation_service._verify_attestation_signature(token)

    assert result["sub"] == "wallet-1"
    assert result["iss"] == "https://wallet.example"


def test_verify_attestation_signature_tampered():
    """A JWT with a tampered signature raises InvalidAttestationError."""
    from authlib.jose import JsonWebKey
    from authlib.jose import jwt as jose_jwt

    key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    public_jwk = key.as_dict(is_private=False)
    header = {"alg": "ES256", "typ": "JWT", "jwk": public_jwk}
    payload = {"iss": "x", "sub": "y", "iat": 1_700_000_000, "exp": 9_999_999_999}
    token = jose_jwt.encode(header, payload, key).decode()

    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.invalidsignature"

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        attestation_service._verify_attestation_signature(tampered)

    assert exc_info.value.error == "invalid_attestation"


def test_verify_attestation_signature_missing_jwk():
    """A JWT without an embedded JWK in the header raises InvalidAttestationError."""
    token = _jwt({"iss": "x", "sub": "y", "iat": 1, "exp": 999})

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        attestation_service._verify_attestation_signature(token)

    assert "missing_attestation_jwk" in exc_info.value.description
