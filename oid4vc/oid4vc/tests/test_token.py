"""Tests for token endpoint."""

import base64
import json
import time
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aries_askar import Key, KeyAlg
from multidict import MultiDict

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.public_routes.token import check_token, handle_proof_of_posession, token


@pytest.fixture
def token_request(context):
    """Create a mock token request."""

    class TokenRequest:
        def __init__(self, form_data=None, match_info=None):
            self._form = form_data or MultiDict(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": "test_code_123",
                }
            )
            self.match_info = match_info or {}

        async def post(self):
            return self._form

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return TokenRequest


@pytest.mark.asyncio
async def test_token_pre_authorized_code_reuse_prevented(
    monkeypatch, context, token_request
):
    """Test that pre-authorized codes cannot be reused."""

    # Create a mock exchange record that already has a token (code already used)
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = None
    mock_record.token = "existing_token_jwt"  # Code already used!
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config.from_settings to return no auth_server_url
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    request = token_request()
    response = await token(cast(web.Request, request))

    # Should return error indicating code was already used
    assert response.status == 400
    assert response.content_type == "application/json"

    # Parse response body
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "already been used" in body["error_description"]


@pytest.mark.asyncio
async def test_token_pre_authorized_code_first_use_success(
    monkeypatch, context, token_request
):
    """Test that pre-authorized codes work on first use."""

    # Create a mock exchange record without a token (first use)
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = None
    mock_record.token = None  # No token yet - first use
    mock_record.refresh_id = "refresh_123"
    mock_record.save = AsyncMock()

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config.from_settings
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Mock wallet operations to avoid did:jwk creation
    mock_wallet = MagicMock()
    mock_wallet.get_local_dids = AsyncMock(return_value=[])
    mock_did_info = MagicMock()
    mock_did_info.did = "did:jwk:test123"
    mock_did_info.method = "jwk"
    mock_wallet.create_local_did = AsyncMock(return_value=mock_did_info)

    # Mock session as an async context manager
    mock_session = MagicMock()
    mock_session.inject = MagicMock(return_value=mock_wallet)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    context.profile.session = MagicMock(return_value=mock_session)

    # Mock retrieve_or_create_did_jwk and jwt_sign using patch
    mock_nonce = MagicMock()
    mock_nonce.nonce_value = "test_c_nonce_value"
    with (
        patch(
            "oid4vc.public_routes.token.retrieve_or_create_did_jwk",
            AsyncMock(return_value=mock_did_info),
        ),
        patch(
            "oid4vc.public_routes.token.jwt_sign",
            AsyncMock(return_value="new_token_jwt"),
        ),
        patch(
            "oid4vc.public_routes.token.create_nonce",
            AsyncMock(return_value=mock_nonce),
        ),
    ):
        request = token_request()
        response = await token(cast(web.Request, request))

        # Should succeed and return token
        assert response.status == 200
        assert response.content_type == "application/json"

        # Parse response body
        import json

        body = json.loads(response.body)
        assert body["access_token"] == "new_token_jwt"
        assert body["token_type"] == "Bearer"
        assert "c_nonce" in body

        # Verify record was saved with new token
        mock_record.save.assert_called_once()


@pytest.mark.asyncio
async def test_token_with_pin_validation_before_reuse_check(
    monkeypatch, context, token_request
):
    """Test that PIN validation happens before reuse check."""

    # Create a mock exchange record with pin required and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request without pin
    request = token_request()
    response = await token(cast(web.Request, request))

    # Should fail on missing PIN before checking reuse
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_request"
    assert "user_pin is required" in body["error_description"]


@pytest.mark.asyncio
async def test_token_with_wrong_pin_before_reuse_check(
    monkeypatch, context, token_request
):
    """Test that wrong PIN is caught before reuse check."""

    # Create a mock exchange record with pin required and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request with wrong pin
    request = token_request(
        form_data=MultiDict(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "test_code_123",
                "user_pin": "9999",  # Wrong PIN
            }
        )
    )
    response = await token(cast(web.Request, request))

    # Should fail on wrong PIN before checking reuse
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "pin is invalid" in body["error_description"]


@pytest.mark.asyncio
async def test_token_with_correct_pin_but_code_reused(
    monkeypatch, context, token_request
):
    """Test that even with correct PIN, reused codes are rejected."""

    # Create a mock exchange record with correct pin and already used
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "1234"
    mock_record.token = "existing_token"  # Already used
    mock_record.refresh_id = "refresh_123"

    # Mock the retrieve_by_code method
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )

    # Mock Config
    mock_config = MagicMock()
    mock_config.auth_server_url = None
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=mock_config),
    )

    # Request with correct pin
    request = token_request(
        form_data=MultiDict(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "test_code_123",
                "user_pin": "1234",  # Correct PIN
            }
        )
    )
    response = await token(cast(web.Request, request))

    # Should fail on reuse check even though PIN was correct
    assert response.status == 400
    import json

    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    assert "already been used" in body["error_description"]


# ===========================================================================
# DPoP compatibility — check_token accepts DPoP scheme (no proof verification)
# ===========================================================================


@pytest.mark.asyncio
async def test_check_token_accepts_dpop_scheme(context):
    """check_token must accept DPoP-scheme tokens and proceed to JWT verification.

    The server advertises dpop_signing_alg_values_supported (HAIP DPOP-5.1),
    so wallets such as Credo present DPoP-bound access tokens.  We accept the
    DPoP scheme and verify the token JWT itself; the DPoP proof in the DPoP
    HTTP header is not yet verified (full DPoP support is tracked separately).
    """
    import sys
    import importlib

    importlib.import_module("oid4vc.public_routes.token")
    token_mod = sys.modules["oid4vc.public_routes.token"]
    from oid4vc.public_routes.token import JWTVerifyResult

    fake_result = JWTVerifyResult(
        headers={},
        payload={"exp": int(time.time()) + 600, "sub": "wallet"},
        verified=True,
    )

    with patch.object(token_mod, "jwt_verify", AsyncMock(return_value=fake_result)):
        with patch("oid4vc.config.Config.from_settings") as mock_cfg:
            mock_cfg.return_value.auth_server_url = None
            # DPoP scheme should not raise — it proceeds to jwt_verify
            result = await check_token(context, "DPoP valid_dpop_token")

    assert result.verified is True


@pytest.mark.asyncio
async def test_check_token_still_accepts_bearer(context):
    """Bearer tokens must still be accepted after the DPoP rejection fix."""
    import sys
    import importlib

    # public_routes.__init__ re-exports the `token` function, shadowing the
    # module via attribute access; use sys.modules to reach the actual module.
    importlib.import_module("oid4vc.public_routes.token")
    token_mod = sys.modules["oid4vc.public_routes.token"]
    from oid4vc.public_routes.token import JWTVerifyResult

    fake_result = JWTVerifyResult(
        headers={},
        payload={"exp": int(time.time()) + 600, "sub": "wallet"},
        verified=True,
    )

    with patch.object(token_mod, "jwt_verify", AsyncMock(return_value=fake_result)):
        with patch("oid4vc.config.Config.from_settings") as mock_cfg:
            mock_cfg.return_value.auth_server_url = None
            result = await check_token(context, "Bearer valid_jwt")

    assert result.verified is True


# ===========================================================================
# C-6 fix — PIN comparison uses hmac.compare_digest
# ===========================================================================


def _make_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_proof_jwt(
    nonce: str,
    aud: str = "http://localhost:8020",
    extra_payload: dict | None = None,
) -> str:
    """Build a self-signed openid4vci-proof+jwt using a fresh P-256 key."""
    key = Key.generate(KeyAlg.P256)
    public_jwk = json.loads(key.get_jwk_public())
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "aud": aud,
        "nonce": nonce,
        **(extra_payload or {}),
    }
    h_enc = _make_b64url(json.dumps(header).encode())
    p_enc = _make_b64url(json.dumps(payload).encode())
    sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type="ES256")
    return f"{h_enc}.{p_enc}.{_make_b64url(sig)}"


@pytest.mark.asyncio
async def test_pin_comparison_uses_hmac(context, monkeypatch, token_request):
    """C-6: Verify hmac.compare_digest is invoked instead of plain == for PIN checks."""
    import hmac as hmac_mod

    compare_calls = []
    original = hmac_mod.compare_digest

    def spy_compare_digest(a, b):
        compare_calls.append((a, b))
        return original(a, b)

    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.pin = "9999"
    mock_record.token = None
    mock_record.refresh_id = "r1"

    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_code",
        AsyncMock(return_value=mock_record),
    )
    monkeypatch.setattr(
        "oid4vc.config.Config.from_settings",
        MagicMock(return_value=MagicMock(auth_server_url=None)),
    )
    # Patch the hmac module object directly so token.py's `hmac.compare_digest` call
    # hits the spy regardless of where it imported hmac from.
    monkeypatch.setattr(hmac_mod, "compare_digest", spy_compare_digest)

    request = token_request(
        form_data=MultiDict(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "code123",
                "user_pin": "1234",
            }
        )
    )
    response = await token(cast(web.Request, request))

    assert response.status == 400
    body = json.loads(response.body)
    assert body["error"] == "invalid_grant"
    # Confirm hmac.compare_digest was called, not plain ==
    assert len(compare_calls) == 1
    assert compare_calls[0] == ("1234", "9999")


# ===========================================================================
# C-4 fix — handle_proof_of_posession validates aud claim
# ===========================================================================


@pytest.mark.asyncio
async def test_proof_with_wrong_aud_rejected(profile):
    """C-4: A proof JWT with a mismatched aud must be rejected with invalid_proof."""
    nonce = "nonce-abc"
    jwt_str = _build_proof_jwt(nonce, aud="https://attacker.example.com")
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint="http://localhost:8020"),
    ):
        with pytest.raises(web.HTTPBadRequest) as exc_info:
            await handle_proof_of_posession(profile, proof, nonce)

    body = json.loads(exc_info.value.text)
    assert body["error"] == "invalid_proof"
    assert "aud" in body["error_description"]


@pytest.mark.asyncio
async def test_proof_with_correct_aud_accepted(profile):
    """C-4: A proof JWT with matching aud must pass the aud check."""
    nonce = "nonce-xyz"
    jwt_str = _build_proof_jwt(nonce, aud="http://localhost:8020")
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint="http://localhost:8020"),
    ):
        result = await handle_proof_of_posession(profile, proof, nonce)

    assert result.verified is True


@pytest.mark.asyncio
async def test_proof_aud_with_explicit_default_port_accepted(profile):
    """Wallets may send aud with explicit :443 — must equal endpoint without it."""
    nonce = "nonce-port"
    jwt_str = _build_proof_jwt(
        nonce, aud="https://myissuerapi.zrok.dev.indicioctech.io:443"
    )
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint="https://myissuerapi.zrok.dev.indicioctech.io"),
    ):
        result = await handle_proof_of_posession(profile, proof, nonce)

    assert result.verified is True


@pytest.mark.asyncio
async def test_proof_with_tenant_scoped_aud_accepted(profile):
    """Diff-3: proof JWT aud set to a tenant-scoped URL must be accepted.

    In multitenant / single-wallet-askar mode the wallet client sets aud to
    {issuer_base}/tenant/{wallet_id}.  The updated check allows any value that
    starts with ``issuer_endpoint + '/tenant/'``.
    """
    nonce = "nonce-tenant"
    jwt_str = _build_proof_jwt(nonce, aud="http://localhost:8020/tenant/my-wallet-id")
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint="http://localhost:8020"),
    ):
        result = await handle_proof_of_posession(profile, proof, nonce)

    assert result.verified is True


@pytest.mark.asyncio
async def test_proof_with_cross_issuer_tenant_path_rejected(profile):
    """Diff-3: a cross-issuer aud with a tenant path must still be rejected.

    ``https://attacker.example.com/tenant/x`` starts with a DIFFERENT base so
    the updated check must not accept it.
    """
    nonce = "nonce-cross"
    jwt_str = _build_proof_jwt(
        nonce, aud="https://attacker.example.com/tenant/my-wallet-id"
    )
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint="http://localhost:8020"),
    ):
        with pytest.raises(web.HTTPBadRequest) as exc_info:
            await handle_proof_of_posession(profile, proof, nonce)

    body = json.loads(exc_info.value.text)
    assert body["error"] == "invalid_proof"
    assert "aud" in body["error_description"]


@pytest.mark.asyncio
async def test_proof_iss_fallback_when_no_key_in_header(profile):
    """Wallets that omit jwk/kid/x5c but put their DID in iss must be resolved."""
    nonce = "nonce-iss-fallback"
    key = Key.generate(KeyAlg.P256)
    public_jwk = json.loads(key.get_jwk_public())
    # Header has NO jwk, kid, or x5c — only alg+typ
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256"}
    payload = {
        "iss": "did:key:zDnaemDNiAWCCLFKP2ppPJuq52E2Gh9trydNgTqrWDkb5oiaQ",
        "aud": "http://localhost:8020",
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "nonce": nonce,
    }
    h_enc = _make_b64url(json.dumps(header).encode())
    p_enc = _make_b64url(json.dumps(payload).encode())
    sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type="ES256")
    jwt_str = f"{h_enc}.{p_enc}.{_make_b64url(sig)}"
    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with (
        patch(
            "oid4vc.public_routes.token.Config.from_settings",
            return_value=MagicMock(endpoint="http://localhost:8020"),
        ),
        patch(
            "oid4vc.public_routes.token.key_material_for_kid",
            new=AsyncMock(return_value=key),
        ),
    ):
        result = await handle_proof_of_posession(profile, proof, nonce)

    assert result.verified is True
    assert result.holder_jwk is not None  # derived from iss-resolved key


@pytest.mark.asyncio
async def test_proof_without_aud_not_rejected_when_endpoint_unconfigured(profile):
    """C-4: When endpoint is not configured, a proof without aud is still accepted."""
    nonce = "nonce-noaud"
    # Build a JWT with no aud claim at all
    key = Key.generate(KeyAlg.P256)
    public_jwk = json.loads(key.get_jwk_public())
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {"iat": int(time.time()), "exp": int(time.time()) + 600, "nonce": nonce}
    h_enc = _make_b64url(json.dumps(header).encode())
    p_enc = _make_b64url(json.dumps(payload).encode())
    sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type="ES256")
    jwt_str = f"{h_enc}.{p_enc}.{_make_b64url(sig)}"

    proof = {"proof_type": "jwt", "jwt": jwt_str}

    with patch(
        "oid4vc.public_routes.token.Config.from_settings",
        return_value=MagicMock(endpoint=None),
    ):
        result = await handle_proof_of_posession(profile, proof, nonce)

    assert result.verified is True
