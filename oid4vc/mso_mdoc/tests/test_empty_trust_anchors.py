"""Tests for the HIGH-severity security gap: empty trust anchors silently pass.

SECURITY GAP (identified in code review):
    In ``MsoMdocCredVerifier.verify_credential`` and the standalone
    ``mdoc_verify()`` helper, when no trust anchors are configured the Rust
    ``verify_issuer_signature`` is called with an empty list.  With an empty
    list the Rust library (isomdl-uniffi / x509_cert) silently accepts any
    self-signed issuer certificate, effectively disabling chain validation and
    allowing an attacker to present any self-signed mDoc as valid.

    The DESIRED behaviour (asserted by the tests in this module) is
    fail-closed:
    - If ``trust_anchors`` is empty AND no explicit bypass flag has been set,
      ``verify_credential`` / ``mdoc_verify`` MUST return ``verified=False``
      with an error message indicating that trust anchors are missing.

HOW TO RUN:
    pytest mso_mdoc/tests/test_empty_trust_anchors.py -v
"""

import sys
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub the Rust native extension before importing any module under test.
# ---------------------------------------------------------------------------
_iso_stub = MagicMock()
_iso_stub.AuthenticationStatus = MagicMock()
_iso_stub.AuthenticationStatus.VALID = "VALID"
_iso_stub.AuthenticationStatus.INVALID = "INVALID"
_iso_stub.MdocVerificationError = type("MdocVerificationError", (Exception,), {})
sys.modules.setdefault("isomdl_uniffi", _iso_stub)

from ..mdoc.cred_verifier import MsoMdocCredVerifier  # noqa: E402
from ..mdoc.pres_verifier import MsoMdocPresVerifier  # noqa: E402
from ..mdoc.mdoc_verify import mdoc_verify  # noqa: E402


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_profile():
    """Return a minimal mock Profile with an async session context manager."""
    profile = MagicMock()
    session = MagicMock()

    @asynccontextmanager
    async def _session():
        yield session

    profile.session = _session
    profile.settings = MagicMock()
    profile.settings.get.return_value = None
    return profile, session


def _make_mock_mdoc(verified: bool = True, common_name: str = "Test CA"):
    """Return a mock Mdoc object whose ``verify_issuer_signature`` returns *verified*."""

    class _VerifResult:
        pass

    vr = _VerifResult()
    vr.verified = verified
    vr.common_name = common_name
    vr.error = None if verified else "Signature verification failed"

    mdoc = MagicMock()
    mdoc.doctype.return_value = "org.iso.18013.5.1.mDL"
    mdoc.id.return_value = "test-id-001"
    mdoc.details.return_value = {}
    mdoc.verify_issuer_signature.return_value = vr
    return mdoc


def _make_presentation_record(nonce: str = "test-nonce"):
    record = MagicMock()
    record.nonce = nonce
    record.presentation_id = "pres-001"
    return record


# ---------------------------------------------------------------------------
# Core security tests — MsoMdocCredVerifier.verify_credential
# ---------------------------------------------------------------------------


class TestEmptyTrustAnchorsCredVerifier:
    """verify_credential must fail-closed when no trust anchors are available."""

    @pytest.mark.asyncio
    async def test_no_trust_store_rejects_credential(self):
        """With trust_store=None, verify_credential MUST return verified=False.

        CURRENT STATE: this test documents the desired secure behaviour.
        The Rust mock is arranged so that it would return 'verified=True' with
        an empty trust-anchor list — simulating the real Rust library accepting
        any self-signed cert when no roots are pinned.  The Python layer MUST
        intercept this and return verified=False.

        If this test fails it means the fail-closed guard is missing.
        """
        verifier = MsoMdocCredVerifier(trust_anchors=[])
        profile, _ = _make_profile()
        mock_mdoc = _make_mock_mdoc(verified=True)  # Rust "accepts" without trust anchors

        with patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso.Mdoc.from_string.return_value = mock_mdoc

            result = await verifier.verify_credential(profile, "a0b1c2d3e4f5")

        # DESIRED: fail-closed guard — no trust anchors → reject.
        assert result.verified is False, (
            "SECURITY BUG: verify_credential returned verified=True despite having "
            "no trust anchors configured. Add a fail-closed guard: when "
            "trust_anchors is empty, return verified=False immediately."
        )
        assert result.payload, "Error payload must be populated"
        error_text = result.payload.get("error", "").lower()
        assert (
            "trust" in error_text or "anchor" in error_text or "configured" in error_text
        ), (
            f"Error message should mention trust anchors, got: {result.payload.get('error')}"
        )

    @pytest.mark.asyncio
    async def test_trust_store_returning_empty_list_rejects_credential(self):
        """A trust_store that returns [] still means no chain validation is possible.

        Even if a TrustStore object is configured, if it returns an empty list
        the verifier must fail-closed.
        """

        verifier = MsoMdocCredVerifier(trust_anchors=[])
        profile, _ = _make_profile()
        mock_mdoc = _make_mock_mdoc(verified=True)

        with patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso.Mdoc.from_string.return_value = mock_mdoc

            result = await verifier.verify_credential(profile, "a0b1c2d3e4f5")

        assert result.verified is False, (
            "SECURITY BUG: verify_credential returned verified=True even though "
            "the trust anchors list is empty. Fail-closed guard must also "
            "cover the case where trust_anchors is []."
        )

    @pytest.mark.asyncio
    async def test_trust_store_with_anchors_proceeds_to_rust_verification(self):
        """When trust anchors are present, Rust result must be honoured.

        This is the positive/happy-path control: a non-empty trust store +
        Rust returning verified=True → Python should return verified=True.
        This test must continue to pass after the fail-closed guard is added.
        """
        pem_cert = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBYzCCAQqgAwIBAgIUFakeRootCA123456789012345678901234567890MA0GCSqGSIb3D\n"
            "-----END CERTIFICATE-----\n"
        )

        verifier = MsoMdocCredVerifier(trust_anchors=[pem_cert])
        profile, _ = _make_profile()
        mock_mdoc = _make_mock_mdoc(verified=True, common_name="Test Root CA")

        with patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso.Mdoc.from_string.return_value = mock_mdoc

            result = await verifier.verify_credential(profile, "a0b1c2d3e4f5")

        # The Rust call must have received the trust anchor, not an empty list
        args, _ = mock_mdoc.verify_issuer_signature.call_args
        trust_anchors_passed = args[0]
        assert len(trust_anchors_passed) > 0, (
            "verify_issuer_signature must be called with the trust anchor list"
        )
        assert result.verified is True

    @pytest.mark.asyncio
    async def test_rust_rejection_with_trust_anchors_propagates(self):
        """Rust returning verified=False with anchors configured → verified=False.

        Ensures the fix for the empty-anchor guard doesn't accidentally swallow
        genuine Rust-level rejection.
        """
        pem_cert = (
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----\n"
        )

        verifier = MsoMdocCredVerifier(trust_anchors=[pem_cert])
        profile, _ = _make_profile()
        mock_mdoc = _make_mock_mdoc(verified=False)

        with patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso:
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso.Mdoc.from_string.return_value = mock_mdoc

            result = await verifier.verify_credential(profile, "a0b1c2d3e4f5")

        assert result.verified is False
        assert result.payload.get("error"), "Error detail must be present on failure"


# ---------------------------------------------------------------------------
# Core security tests — standalone mdoc_verify()
# ---------------------------------------------------------------------------


class TestMdocVerifyEmptyTrustAnchors:
    """The standalone mdoc_verify() helper must also fail-closed."""

    def test_mdoc_verify_no_trust_anchors_returns_not_verified(self):
        """mdoc_verify(mso_mdoc, trust_anchors=None) must return verified=False.

        trust_anchors=None should be treated identically to trust_anchors=[].
        Both mean 'no chain validation possible'.
        """
        mock_mdoc = _make_mock_mdoc(verified=True)

        with (
            patch("mso_mdoc.mdoc.mdoc_verify.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso_cred,
        ):
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.Mdoc.from_string.return_value = mock_mdoc
            mock_iso_cred.Mdoc.new_from_base64url_encoded_issuer_signed.return_value = (
                mock_mdoc
            )

            result = mdoc_verify("a0b1c2d3e4f5", trust_anchors=None)

        assert result.verified is False, (
            "SECURITY BUG: mdoc_verify() returned verified=True with "
            "trust_anchors=None. Add a fail-closed guard."
        )

    def test_mdoc_verify_empty_trust_anchors_list_returns_not_verified(self):
        """mdoc_verify(mso_mdoc, trust_anchors=[]) must return verified=False."""
        mock_mdoc = _make_mock_mdoc(verified=True)

        with (
            patch("mso_mdoc.mdoc.mdoc_verify.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso_cred,
        ):
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.Mdoc.from_string.return_value = mock_mdoc
            mock_iso_cred.Mdoc.new_from_base64url_encoded_issuer_signed.return_value = (
                mock_mdoc
            )

            result = mdoc_verify("a0b1c2d3e4f5", trust_anchors=[])

        assert result.verified is False, (
            "SECURITY BUG: mdoc_verify() returned verified=True with empty "
            "trust_anchors. Add a fail-closed guard: when trust_anchors is "
            "empty, return MdocVerifyResult(verified=False, error='No trust anchors...') "
            "without calling verify_issuer_signature."
        )
        assert result.error, "Error message must be populated"
        low = result.error.lower()
        assert "trust" in low or "anchor" in low or "configured" in low, (
            f"Error should reference trust anchors, got: {result.error!r}"
        )

    def test_mdoc_verify_with_trust_anchors_passes_rust_result_through(self):
        """mdoc_verify() with non-empty trust_anchors honours the Rust result."""
        pem_cert = (
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----\n"
        )
        mock_mdoc = _make_mock_mdoc(verified=True, common_name="My CA")

        with (
            patch("mso_mdoc.mdoc.mdoc_verify.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso_cred,
        ):
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.Mdoc.from_string.return_value = mock_mdoc
            mock_iso_cred.Mdoc.new_from_base64url_encoded_issuer_signed.return_value = (
                mock_mdoc
            )

            result = mdoc_verify("a0b1c2d3e4f5", trust_anchors=[pem_cert])

        assert result.verified is True
        assert result.payload["status"] == "verified"

    def test_mdoc_verify_parse_failure_returns_not_verified(self):
        """Parsing failure always returns verified=False regardless of trust anchors."""
        with (
            patch("mso_mdoc.mdoc.mdoc_verify.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_iso_cred,
        ):
            mock_iso.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.MdocVerificationError = _iso_stub.MdocVerificationError
            mock_iso_cred.Mdoc.from_string.side_effect = Exception("CBOR parse error")
            mock_iso_cred.Mdoc.new_from_base64url_encoded_issuer_signed.side_effect = (
                Exception("base64 parse error")
            )

            result = mdoc_verify("not-valid-hex!!", trust_anchors=None)

        assert result.verified is False


# ---------------------------------------------------------------------------
# MsoMdocPresVerifier — verify_presentation also must fail-closed
# ---------------------------------------------------------------------------


class TestEmptyTrustAnchorsPresVerifier:
    """verify_presentation must also reject when no trust anchors are configured."""

    @pytest.mark.asyncio
    async def test_no_trust_store_rejects_presentation(self):
        """OID4VP presentation MUST be rejected when no trust anchors exist."""
        verifier = MsoMdocPresVerifier(trust_anchors=[])
        profile, _ = _make_profile()
        pres_record = _make_presentation_record()

        with (
            patch("mso_mdoc.mdoc.pres_verifier.isomdl_uniffi") as mock_iso,
            patch("mso_mdoc.mdoc.pres_verifier.Config") as mock_config,
            patch(
                "mso_mdoc.mdoc.pres_verifier.retrieve_or_create_did_jwk"
            ) as mock_jwk_fn,
        ):
            mock_config.from_settings.return_value.endpoint = "https://issuer.example"
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_jwk_fn.return_value = mock_jwk
            mock_iso.AuthenticationStatus.VALID = "VALID"

            verified_data = MagicMock()
            verified_data.issuer_authentication = "VALID"
            verified_data.device_authentication = "VALID"
            verified_data.errors = []
            verified_data.doc_type = "org.iso.18013.5.1.mDL"
            verified_data.verified_response = {}
            mock_iso.verify_oid4vp_response.return_value = verified_data

            # Presentation bytes (base64url encoded)
            import base64

            pres_bytes = base64.urlsafe_b64encode(b"\xa0").rstrip(b"=").decode()

            result = await verifier.verify_presentation(profile, pres_bytes, pres_record)

        assert result.verified is False, (
            "SECURITY BUG: verify_presentation returned verified=True with no "
            "trust anchors configured. OID4VP verification must fail-closed."
        )
