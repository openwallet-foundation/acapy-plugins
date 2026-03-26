"""Tests for did:jwk holder_kid end-to-end support.

ACA-Py supports the did:jwk DID method natively. When a wallet presents a JWT
proof with a `kid` of the form ``did:jwk:<base64url(JWK)>#0`` the issuer must
decode the embedded JWK from the DID identifier and use it for mDoc device-key
binding.

Bug (before fix)
----------------
``_extract_device_key`` applied a generic DID regex and returned the URI
fragment ``"0"`` for every did:jwk kid.  ``json.loads("0")`` silently parses
to the Python integer ``0``, which was then passed to the Rust isomdl library
as the holder JWK.  The library raised an opaque error that was caught by the
outer ``except Exception`` handler and re-raised as a generic
``CredProcessorError("Failed to issue mso_mdoc credential: ...")``, giving the
caller no indication that the root cause was an unrecognised DID method.

Fix
---
``_extract_device_key`` now detects the ``jwk`` method, base64url-decodes the
identifier, and returns the embedded JWK JSON string so that isomdl receives a
proper key dict.  Malformed identifiers raise an explicit
``CredProcessorError`` immediately, with a message that names the problematic
DID.
"""

import base64
import json
from unittest.mock import MagicMock

import pytest

from ..cred_processor import MsoMdocCredProcessor
from oid4vc.cred_processor import CredProcessorError

# ---------------------------------------------------------------------------
# Shared test fixture — a genuine P-256 public key JWK and its did:jwk form
# ---------------------------------------------------------------------------

# A minimal, standards-compliant P-256 EC public key JWK (RFC 7517)
_HOLDER_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}
# did:jwk encodes the JWK as a base64url value between "did:jwk:" and "#0".
_JWK_IDENTIFIER = (
    base64.urlsafe_b64encode(json.dumps(_HOLDER_JWK, separators=(",", ":")).encode())
    .rstrip(b"=")
    .decode()
)
_DID_JWK = f"did:jwk:{_JWK_IDENTIFIER}#0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pop(holder_jwk=None, holder_kid=None):
    pop = MagicMock()
    pop.holder_jwk = holder_jwk
    pop.holder_kid = holder_kid
    return pop


def _make_ex(verification_method=None):
    ex = MagicMock()
    ex.verification_method = verification_method
    return ex


# ---------------------------------------------------------------------------
# Tests: bug regression — document the WRONG behaviour before the fix
# ---------------------------------------------------------------------------


class TestDidJwkBugRegression:
    """Pin the observable symptoms that existed BEFORE the fix.

    These tests are written from the *caller's* perspective so they remain
    valid as pure regression tests even after the fix is applied — they now
    assert the *correct* behaviour and would fail if someone accidentally
    reverted the fix.
    """

    def test_did_jwk_kid_returns_jwk_json_not_fragment(self):
        """holder_kid=did:jwk:... must yield the embedded JWK, not '0'.

        Before the fix ``_extract_device_key`` returned the string ``"0"``
        (the URI fragment of a did:jwk DID).  After the fix it must return a
        JSON string that deserialises to an EC JWK dict.
        """
        proc = MsoMdocCredProcessor()
        pop = _make_pop(holder_kid=_DID_JWK)
        ex = _make_ex()

        result = proc._extract_device_key(pop, ex)

        # Must be parseable JSON
        assert result is not None, "must return a value, not None"
        parsed = json.loads(result)

        # Must be a dict (JWK), not the integer 0 that the old code produced
        assert isinstance(parsed, dict), (
            f"_extract_device_key returned json-parseable value {parsed!r} "
            f"(type {type(parsed).__name__}), expected a JWK dict. "
            "This is the did:jwk bug: the fragment '0' was silently "
            "parsed as integer 0."
        )

    def test_did_jwk_decoded_jwk_matches_original(self):
        """The JWK decoded from did:jwk must equal the original key material."""
        proc = MsoMdocCredProcessor()
        pop = _make_pop(holder_kid=_DID_JWK)
        ex = _make_ex()

        result = proc._extract_device_key(pop, ex)
        parsed = json.loads(result)

        assert parsed["kty"] == _HOLDER_JWK["kty"]
        assert parsed["crv"] == _HOLDER_JWK["crv"]
        assert parsed["x"] == _HOLDER_JWK["x"]
        assert parsed["y"] == _HOLDER_JWK["y"]

    def test_did_jwk_fragment_zero_is_not_returned_as_string(self):
        """The literal string '0' must never be returned for a did:jwk kid.

        Returning '0' is the sentinel of the old bug: json.loads('0') == 0
        which isomdl then receives as the holder key and fails cryptically.
        """
        proc = MsoMdocCredProcessor()
        pop = _make_pop(holder_kid=_DID_JWK)
        ex = _make_ex()

        result = proc._extract_device_key(pop, ex)

        assert result != "0", (
            "_extract_device_key returned '0' — this is the bug. "
            "The did:jwk fragment '0' must not be returned; the full "
            "embedded JWK must be decoded from the identifier instead."
        )

    def test_integer_zero_is_never_silent_signing_key(self):
        """json.loads of device_key_str must never yield integer 0.

        Guard against the entire class of issues where json.loads succeeds
        on the fragment but produces a non-dict value.
        """
        proc = MsoMdocCredProcessor()
        pop = _make_pop(holder_kid=_DID_JWK)
        ex = _make_ex()

        result = proc._extract_device_key(pop, ex)
        parsed = json.loads(result)

        assert parsed != 0, (
            "Parsed device key is integer 0, which isomdl will reject "
            "with an opaque Rust error. Root cause: did:jwk fragment '0' "
            "leaked through as the holder key."
        )


# ---------------------------------------------------------------------------
# Tests: correct end-to-end behaviour after the fix
# ---------------------------------------------------------------------------


class TestDidJwkEndToEnd:
    """Verify that did:jwk kids work correctly in all relevant code paths."""

    def test_holder_kid_did_jwk_with_fragment(self):
        """Standard did:jwk#0 kid → embedded JWK returned as JSON string."""
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(_make_pop(holder_kid=_DID_JWK), _make_ex())

        assert isinstance(result, str)
        jwk = json.loads(result)
        assert isinstance(jwk, dict)
        assert jwk.get("kty") == "EC"
        assert jwk.get("crv") == "P-256"

    def test_holder_kid_did_jwk_without_fragment(self):
        """did:jwk without fragment also decodes the embedded JWK."""
        did_no_fragment = f"did:jwk:{_JWK_IDENTIFIER}"
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(
            _make_pop(holder_kid=did_no_fragment), _make_ex()
        )

        assert result is not None
        jwk = json.loads(result)
        assert isinstance(jwk, dict)
        assert jwk.get("kty") == "EC"

    def test_holder_jwk_still_takes_priority_over_did_jwk_kid(self):
        """Inline holder_jwk overrides a did:jwk holder_kid (priority unchanged)."""
        inline_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(
            _make_pop(holder_jwk=inline_jwk, holder_kid=_DID_JWK), _make_ex()
        )

        parsed = json.loads(result)
        # Must come from the inline JWK, not from decoding the did:jwk
        assert parsed["x"] == inline_jwk["x"], (
            "holder_jwk should take priority over holder_kid for did:jwk"
        )

    def test_verification_method_did_jwk_fallback(self):
        """did:jwk in verification_method (no holder_kid or holder_jwk) is decoded."""
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(
            _make_pop(),  # no holder_jwk, no holder_kid
            _make_ex(verification_method=_DID_JWK),
        )

        assert result is not None
        jwk = json.loads(result)
        assert isinstance(jwk, dict)
        assert jwk.get("kty") == "EC"

    def test_did_key_still_returns_fragment(self):
        """Non-did:jwk methods still return the fragment (existing behaviour preserved)."""
        did_key = "did:key:z6Mktest#keyref"
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(_make_pop(holder_kid=did_key), _make_ex())

        assert result == "keyref", f"did:key fragment handling regressed; got {result!r}"

    def test_did_key_without_fragment_returns_full_did(self):
        """did:key without a fragment returns the whole DID string."""
        did_key = "did:key:z6Mktest"
        proc = MsoMdocCredProcessor()
        result = proc._extract_device_key(_make_pop(holder_kid=did_key), _make_ex())

        assert result == did_key, f"Expected full DID, got {result!r}"

    def test_malformed_did_jwk_raises_cred_processor_error(self):
        """Corrupt base64url in did:jwk identifier raises CredProcessorError immediately.

        Before the fix a malformed identifier would either silently produce
        garbage or cause an opaque Rust error.  After the fix a clear,
        actionable error is raised.
        """
        bad_did = "did:jwk:!!!not-valid-base64!!!#0"
        proc = MsoMdocCredProcessor()

        with pytest.raises(CredProcessorError, match="did:jwk"):
            proc._extract_device_key(_make_pop(holder_kid=bad_did), _make_ex())

    def test_malformed_did_jwk_error_does_not_swallow_cause(self):
        """The CredProcessorError raised for a bad did:jwk must chain the cause."""
        bad_did = "did:jwk:!!!bad!!!#0"
        proc = MsoMdocCredProcessor()

        with pytest.raises(CredProcessorError) as exc_info:
            proc._extract_device_key(_make_pop(holder_kid=bad_did), _make_ex())

        # __cause__ is set (raise ... from exc)
        assert exc_info.value.__cause__ is not None, (
            "CredProcessorError for bad did:jwk must chain the original decode error"
        )

    def test_did_jwk_identifier_with_padding_variants(self):
        """did:jwk identifiers that need 0, 1, 2, or 3 bytes of padding all work."""
        # Build JWK payloads of varying lengths so base64url encoding produces
        # different trailing padding counts (0, 1, 2 extra '=' chars)
        for extra_field_length in range(4):  # varies output modulo 4
            extra = "A" * extra_field_length
            jwk_variant = {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "_t": extra,  # extra field to vary payload length
            }
            identifier = (
                base64.urlsafe_b64encode(
                    json.dumps(jwk_variant, separators=(",", ":")).encode()
                )
                .rstrip(b"=")
                .decode()
            )
            did = f"did:jwk:{identifier}#0"
            proc = MsoMdocCredProcessor()
            result = proc._extract_device_key(_make_pop(holder_kid=did), _make_ex())

            assert result is not None, f"Failed for padding variant {extra_field_length}"
            parsed = json.loads(result)
            assert isinstance(parsed, dict), f"Got {parsed!r}, expected dict"
            assert parsed["kty"] == "EC"
