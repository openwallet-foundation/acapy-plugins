"""Tests for attestation service (kid + allow list design)."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from joserfc import jwk as jose_jwk
from joserfc import jwt as jose_jwt

from tenant.services import attestation_service


def _b64(data: dict) -> str:
    encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")


# --- Helpers to generate real signed JWTs ---


def _generate_provider_key():
    """Generate a wallet provider EC key pair."""
    key = jose_jwk.ECKey.generate_key("P-256")
    return key, key.as_dict(private=False)


def _generate_wallet_key():
    """Generate a wallet instance EC key pair."""
    key = jose_jwk.ECKey.generate_key("P-256")
    return key, key.as_dict(private=False)


def _sign_attestation(provider_key, kid, payload):
    """Sign an attestation JWT with the provider's key."""
    header = {"alg": "ES256", "typ": "oauth-client-attestation+jwt", "kid": kid}
    return jose_jwt.encode(header, payload, provider_key)


def _sign_pop(wallet_key, payload):
    """Sign an attestation PoP JWT with the wallet instance's key."""
    header = {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt"}
    return jose_jwt.encode(header, payload, wallet_key)


def _make_attestation_and_pop(
    provider_key,
    kid,
    wallet_key,
    wallet_public,
    *,
    iss="https://wallet-provider.example",
    sub="Ontario Wallet",
    att_iat=1_699_999_900,
    att_exp=1_700_000_300,
    pop_iss=None,
    pop_aud="https://as.example.com",
    pop_jti="unique-jti-1",
    pop_iat=1_700_000_000,
):
    """Build both attestation + PoP JWTs with sensible defaults."""
    attestation = _sign_attestation(
        provider_key,
        kid,
        {
            "iss": iss,
            "sub": sub,
            "cnf": {"jwk": wallet_public},
            "iat": att_iat,
            "exp": att_exp,
        },
    )
    pop = _sign_pop(
        wallet_key,
        {
            "iss": pop_iss if pop_iss is not None else sub,
            "aud": pop_aud,
            "jti": pop_jti,
            "iat": pop_iat,
        },
    )
    return attestation, pop


@pytest.fixture
def default_settings(monkeypatch):
    monkeypatch.setattr(
        attestation_service.settings,
        "ATTESTATION_CLOCK_SKEW_SECONDS",
        60,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "INTERNAL_BASE_URL",
        "http://admin:9000/internal",
        raising=False,
    )
    monkeypatch.setattr(
        attestation_service.settings,
        "INTERNAL_AUTH_TOKEN",
        "test-token",
        raising=False,
    )
    # Swap DB-backed JTI cache for async-compatible in-memory version in tests

    _seen: set[str] = set()

    async def _async_check_and_store(jti, db=None, now=None, expires_at=None):
        if not jti:
            return False
        if jti in _seen:
            return False
        _seen.add(jti)
        return True

    test_cache = MagicMock()
    test_cache.check_and_store = _async_check_and_store
    monkeypatch.setattr(attestation_service, "_attest_pop_jti_cache", test_cache)


@pytest.fixture
def provider_keys():
    """Fixture: generate provider key pair."""
    key, public = _generate_provider_key()
    return key, public


async def test_optional_missing_returns_none(default_settings):
    result = await attestation_service.validate_client_attestation(
        client_attestation=None,
        attestation_required=False,
        expected_audience="https://as.example.com",
    )
    assert result is None


async def test_required_missing_raises(default_settings):
    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=None,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert exc_info.value.error == "invalid_client_attestation"


async def test_invalid_kid_type_raises(default_settings):
    """Attestation JWT with non-string kid in header should fail."""
    # Build a JWT with kid as integer (invalid type)
    header = _b64({"alg": "ES256", "typ": "oauth-client-attestation+jwt", "kid": 123})
    payload = _b64(
        {"iss": "https://provider.example", "sub": "wallet", "iat": 1, "exp": 2}
    )
    token = f"{header}.{payload}.fakesig"

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "invalid_kid" in exc_info.value.description


async def test_untrusted_provider_raises(default_settings, provider_keys, monkeypatch):
    """Attestation from unknown provider (not in allow list) should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, _ = provider_keys

    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://unknown-provider.example",
            "sub": "wallet-app",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    # Mock the lookup to return not found
    mock_lookup = AsyncMock(return_value=None)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "untrusted_provider" in exc_info.value.description
    mock_lookup.assert_awaited_once_with("https://unknown-provider.example", "key-1")


async def test_valid_attestation_with_provider_lookup(
    default_settings, provider_keys, monkeypatch
):
    """Valid attestation + PoP with kid lookup from allow list succeeds."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation, pop = _make_attestation_and_pop(
        provider_key,
        "key-1",
        wallet_key,
        wallet_public,
    )

    # Mock the lookup to return the provider's public key
    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    result = await attestation_service.validate_client_attestation(
        client_attestation=attestation,
        client_attestation_pop=pop,
        attestation_required=True,
        expected_audience="https://as.example.com",
    )

    assert result is not None
    assert result["verified"] is True
    assert result["iss"] == "https://wallet-provider.example"
    assert result["kid"] == "key-1"
    assert result["sub"] == "Ontario Wallet"
    assert result["pop_jti"] == "unique-jti-1"
    assert result["cnf_jkt"] is not None
    mock_lookup.assert_awaited_once_with("https://wallet-provider.example", "key-1")


async def test_invalid_signature_raises(default_settings, provider_keys, monkeypatch):
    """Attestation signed with wrong key should fail signature verification."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    _, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    # Sign with a DIFFERENT key
    wrong_key, _ = _generate_provider_key()
    token = _sign_attestation(
        wrong_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "jti": "jti-1",
            "iat": 1_700_000_000,
        },
    )

    # Return the REAL provider's public key — signature won't match
    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "signature_invalid" in exc_info.value.description


async def test_expired_attestation_raises(default_settings, provider_keys, monkeypatch):
    """Expired attestation should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_001_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,  # expired by now (1_700_001_000)
        },
    )

    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "jti": "jti-1",
            "iat": 1_700_001_000,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "expired" in exc_info.value.description


# --- New tests for typ, cnf, and PoP validation ---


async def test_invalid_attestation_typ_raises(default_settings, monkeypatch):
    """Attestation JWT with wrong typ header should fail."""
    provider_key, _ = _generate_provider_key()
    # Sign with wrong typ
    header = {"alg": "ES256", "typ": "jwt", "kid": "key-1"}
    token = jose_jwt.encode(
        header,
        {
            "iss": "https://provider.example",
            "sub": "wallet",
            "iat": 1,
            "exp": 2,
        },
        provider_key,
    )

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "invalid_attestation_typ" in exc_info.value.description


async def test_missing_cnf_jwk_raises(default_settings, provider_keys, monkeypatch):
    """Attestation without cnf.jwk should fail (now required)."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys

    # Attestation without cnf claim
    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            client_attestation_pop=None,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "missing_cnf_jwk" in exc_info.value.description


async def test_missing_pop_raises(default_settings, provider_keys, monkeypatch):
    """Attestation present but PoP missing should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    _, wallet_public = _generate_wallet_key()

    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            client_attestation_pop=None,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "missing_client_attestation_pop" in exc_info.value.description


async def test_pop_wrong_signature_raises(default_settings, provider_keys, monkeypatch):
    """PoP signed with wrong key should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    _, wallet_public = _generate_wallet_key()

    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    # Sign PoP with a DIFFERENT key (not the wallet key)
    wrong_key, _ = _generate_wallet_key()
    pop = _sign_pop(
        wrong_key,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "jti": "jti-1",
            "iat": 1_700_000_000,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "pop_signature_invalid" in exc_info.value.description


async def test_pop_missing_aud_raises(default_settings, provider_keys, monkeypatch):
    """PoP without aud claim should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )
    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "jti": "jti-1",
            "iat": 1_700_000_000,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=attestation,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "missing_attestation_pop_aud" in exc_info.value.description


async def test_pop_aud_mismatch_raises(default_settings, provider_keys, monkeypatch):
    """PoP aud that doesn't match expected_audience should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation, pop = _make_attestation_and_pop(
        provider_key,
        "key-1",
        wallet_key,
        wallet_public,
        pop_aud="https://other-as.example.com",
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=attestation,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "attestation_pop_aud_mismatch" in exc_info.value.description


async def test_pop_aud_array_accepted(default_settings, provider_keys, monkeypatch):
    """PoP aud as array containing expected_audience should succeed."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )
    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "aud": ["https://as.example.com", "https://other.example.com"],
            "jti": "jti-1",
            "iat": 1_700_000_000,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    result = await attestation_service.validate_client_attestation(
        client_attestation=attestation,
        client_attestation_pop=pop,
        attestation_required=True,
        expected_audience="https://as.example.com",
    )
    assert result is not None
    assert result["verified"] is True


async def test_pop_missing_jti_raises(default_settings, provider_keys, monkeypatch):
    """PoP without jti claim should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )
    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "iat": 1_700_000_000,
        },
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=attestation,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "missing_attestation_pop_jti" in exc_info.value.description


async def test_pop_invalid_typ_raises(default_settings, provider_keys, monkeypatch):
    """PoP with wrong typ header should fail."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )
    # Sign PoP with wrong typ
    pop_header = {"alg": "ES256", "typ": "jwt"}
    pop = jose_jwt.encode(
        pop_header,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "jti": "jti-1",
            "iat": 1_700_000_000,
        },
        wallet_key,
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=attestation,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "invalid_attestation_pop_typ" in exc_info.value.description


async def test_pop_jti_replay_raises(default_settings, provider_keys, monkeypatch):
    """Replayed PoP jti should be rejected."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    attestation, pop = _make_attestation_and_pop(
        provider_key,
        "key-1",
        wallet_key,
        wallet_public,
        pop_jti="replay-jti-1",
    )

    mock_lookup = AsyncMock(return_value=provider_public)
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    # First call succeeds
    result = await attestation_service.validate_client_attestation(
        client_attestation=attestation,
        client_attestation_pop=pop,
        attestation_required=True,
        expected_audience="https://as.example.com",
    )
    assert result is not None
    assert result["verified"] is True

    # Second call with same jti is rejected
    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=attestation,
            client_attestation_pop=pop,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
    assert "attestation_pop_jti_replay" in exc_info.value.description


async def test_attestation_without_kid_verifies_by_trial(
    default_settings, provider_keys, monkeypatch
):
    """draft-07 5.1 makes `kid` optional; unlabelled keys are tried in turn."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, provider_public = provider_keys
    wallet_key, wallet_public = _generate_wallet_key()

    # Attestation header carries no kid.
    attestation = jose_jwt.encode(
        {"alg": "ES256", "typ": "oauth-client-attestation+jwt"},
        {
            "iss": "https://wallet-provider.example",
            "sub": "Ontario Wallet",
            "cnf": {"jwk": wallet_public},
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
        provider_key,
    )
    pop = _sign_pop(
        wallet_key,
        {
            "iss": "Ontario Wallet",
            "aud": "https://as.example.com",
            "jti": "nokid-jti-1",
            "iat": 1_700_000_000,
        },
    )

    # No kid -> admin returns the full key set for trial verification.
    decoy, _ = _generate_provider_key()
    mock_lookup = AsyncMock(return_value=[decoy.as_dict(private=False), provider_public])
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    result = await attestation_service.validate_client_attestation(
        client_attestation=attestation,
        client_attestation_pop=pop,
        attestation_required=True,
        expected_audience="https://as.example.com",
    )

    assert result is not None and result["verified"] is True
    assert result["kid"] is None
    mock_lookup.assert_awaited_once_with("https://wallet-provider.example", None)


async def test_pop_without_attestation_raises(default_settings):
    """draft-07 9 step 1: both headers are required together."""
    with pytest.raises(attestation_service.InvalidAttestationError) as exc_info:
        await attestation_service.validate_client_attestation(
            client_attestation=None,
            client_attestation_pop="some-pop-jwt",
            attestation_required=False,
            expected_audience="https://as.example.com",
        )
    assert "missing_client_attestation" in exc_info.value.description


async def test_provider_lookup_failure_is_not_a_client_error(
    default_settings, provider_keys, monkeypatch
):
    """A lookup outage must not be reported as an untrusted provider."""
    monkeypatch.setattr(attestation_service, "_now_ts", lambda: 1_700_000_000)
    provider_key, _ = provider_keys

    token = _sign_attestation(
        provider_key,
        "key-1",
        {
            "iss": "https://wallet-provider.example",
            "sub": "wallet-app",
            "iat": 1_699_999_900,
            "exp": 1_700_000_300,
        },
    )

    mock_lookup = AsyncMock(
        side_effect=attestation_service.AttestationLookupError("admin down")
    )
    monkeypatch.setattr(attestation_service, "_lookup_provider_key", mock_lookup)

    with pytest.raises(attestation_service.AttestationLookupError):
        await attestation_service.validate_client_attestation(
            client_attestation=token,
            attestation_required=True,
            expected_audience="https://as.example.com",
        )
