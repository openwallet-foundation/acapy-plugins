"""Unit tests for check_status_list_claim (IETF Token Status List revocation).

These tests exercise the helper function in isolation by mocking the aiohttp
HTTP fetch so they do not require a running status list server.
"""

import base64
import json
import zlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ..mdoc.utils import check_status_list_claim


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_status_list_jwt(
    bits: int = 1, revoked_indices: list[int] | None = None
) -> str:
    """Return an unsigned (alg=none) IETF Token Status List JWT.

    Args:
        bits: Number of bits per credential entry (1 or 2).
        revoked_indices: List of credential indices to mark as revoked (bit set to 1).

    Returns:
        JWT string ``header.payload.`` with an empty signature.
    """
    revoked_indices = revoked_indices or []
    # 1024 entries of *bits* bits each
    total_bytes = (1024 * bits + 7) // 8
    raw = bytearray(total_bytes)

    for idx in revoked_indices:
        bit_pos = idx * bits
        byte_idx = bit_pos // 8
        bit_in_byte = bit_pos % 8
        # Set the first bit of the entry to 1 (revoked)
        raw[byte_idx] |= 1 << bit_in_byte

    compressed = zlib.compress(bytes(raw))
    lst = base64.urlsafe_b64encode(compressed).decode().rstrip("=")

    payload = {
        "iss": "did:key:testissuer",
        "status_list": {"bits": bits, "lst": lst},
    }

    header_b64 = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode())
        .decode()
        .rstrip("=")
    )
    body_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{body_b64}."


def _mock_http_response(jwt_text: str):
    """Build a mock aiohttp response that returns *jwt_text* as text."""
    mock_resp = AsyncMock()
    mock_resp.text = AsyncMock(return_value=jwt_text)
    mock_resp.raise_for_status = MagicMock()
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    return mock_resp


def _mock_http_session(jwt_text: str):
    """Return a context-manager mock for aiohttp.ClientSession.

    Patches ``aiohttp.ClientSession`` so that ``async with session.get(url)``
    returns a response that yields *jwt_text*.
    """
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.get = MagicMock(return_value=_mock_http_response(jwt_text))
    return mock_session


# ---------------------------------------------------------------------------
# Namespace-keyed claim dicts (mimicking extract_verified_claims output)
# ---------------------------------------------------------------------------


def _make_claims(idx: int, uri: str, namespace: str = "org.iso.18013.5.1") -> dict:
    return {
        namespace: {
            "given_name": "Alice",
            "status": {"status_list": {"idx": idx, "uri": uri}},
        }
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCheckStatusListClaim:
    """Tests for check_status_list_claim()."""

    @pytest.mark.asyncio
    async def test_returns_none_when_no_status_claim(self):
        """Claims without a status entry → None (credential valid)."""
        claims = {"org.iso.18013.5.1": {"given_name": "Alice"}}
        result = await check_status_list_claim(claims)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_empty_claims(self):
        """Empty claims dict → None."""
        result = await check_status_list_claim({})
        assert result is None

    @pytest.mark.asyncio
    async def test_valid_credential_returns_none(self):
        """Credential at idx=42 not in revoked list → None (credential valid)."""
        jwt_text = _build_status_list_jwt(revoked_indices=[])  # no revocations
        claims = _make_claims(idx=42, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is None

    @pytest.mark.asyncio
    async def test_revoked_credential_returns_error_string(self):
        """Credential at idx=42 in revoked list → non-None error string."""
        jwt_text = _build_status_list_jwt(revoked_indices=[42])
        claims = _make_claims(idx=42, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is not None
        assert "revoked" in result.lower() or "suspended" in result.lower()
        assert "42" in result

    @pytest.mark.asyncio
    async def test_different_credential_not_revoked(self):
        """Only idx=10 is revoked; checking idx=42 should still pass."""
        jwt_text = _build_status_list_jwt(revoked_indices=[10])
        claims = _make_claims(idx=42, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is None

    @pytest.mark.asyncio
    async def test_status_found_in_non_mdl_namespace(self):
        """Status claim in a generic namespace is detected correctly."""
        jwt_text = _build_status_list_jwt(revoked_indices=[7])
        claims = {
            "org.example.generic": {
                "name": "Bob",
                "status": {"status_list": {"idx": 7, "uri": "http://issuer/status/1"}},
            }
        }

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is not None
        assert "7" in result

    @pytest.mark.asyncio
    async def test_2bit_status_valid(self):
        """2-bit entry table: idx=5 with value 0 → valid."""
        jwt_text = _build_status_list_jwt(bits=2, revoked_indices=[])
        claims = _make_claims(idx=5, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is None

    @pytest.mark.asyncio
    async def test_2bit_status_revoked(self):
        """2-bit entry table: idx=5 with first bit set → revoked."""
        jwt_text = _build_status_list_jwt(bits=2, revoked_indices=[5])
        claims = _make_claims(idx=5, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is not None

    @pytest.mark.asyncio
    async def test_network_error_is_fail_open(self):
        """HTTP fetch failure → None (fail-open, log warning but allow credential)."""
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock(
            side_effect=Exception("Connection refused")
        )
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_session.get = MagicMock(return_value=mock_resp)

        claims = _make_claims(idx=0, uri="http://unreachable/status/0")

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await check_status_list_claim(claims)

        assert result is None  # Fail-open on network errors

    @pytest.mark.asyncio
    async def test_malformed_jwt_is_fail_open(self):
        """Malformed JWT response → None (fail-open)."""
        jwt_text = "not.a.valid.jwt.at.all.blah"
        claims = _make_claims(idx=0, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is None

    @pytest.mark.asyncio
    async def test_missing_idx_is_skipped(self):
        """status_list claim without idx → None (skip revocation check)."""
        claims = {
            "org.iso.18013.5.1": {
                "status": {"status_list": {"uri": "http://issuer/status/0"}},
            }
        }
        result = await check_status_list_claim(claims)
        assert result is None

    @pytest.mark.asyncio
    async def test_missing_uri_is_skipped(self):
        """status_list claim without uri → None (skip revocation check)."""
        claims = {
            "org.iso.18013.5.1": {
                "status": {"status_list": {"idx": 5}},
            }
        }
        result = await check_status_list_claim(claims)
        assert result is None

    @pytest.mark.asyncio
    async def test_status_claim_not_a_dict_is_skipped(self):
        """status value that is not a dict → None (no status_list key to find)."""
        claims = {
            "org.iso.18013.5.1": {
                "status": "some-string-not-a-dict",
            }
        }
        result = await check_status_list_claim(claims)
        assert result is None

    @pytest.mark.asyncio
    async def test_index_zero_valid(self):
        """idx=0 not revoked → valid."""
        jwt_text = _build_status_list_jwt(revoked_indices=[])
        claims = _make_claims(idx=0, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is None

    @pytest.mark.asyncio
    async def test_index_zero_revoked(self):
        """idx=0 revoked → error string."""
        jwt_text = _build_status_list_jwt(revoked_indices=[0])
        claims = _make_claims(idx=0, uri="http://issuer/status/0")

        with patch("aiohttp.ClientSession", return_value=_mock_http_session(jwt_text)):
            result = await check_status_list_claim(claims)

        assert result is not None
