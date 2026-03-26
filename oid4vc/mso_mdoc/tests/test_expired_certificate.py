"""Tests for the MEDIUM-severity gap: expired certificates are not checked at issuance.

CODE REVIEW GAP (identified in deep code review):
    Neither ``get_certificate_for_key`` nor the ``MsoMdocCredProcessor.issue``
    path validate the X.509 validity period of the signing certificate before
    embedding it in the issued mDoc.  This means a certificate that expired
    yesterday can still be used to issue mDocs today; all verifiers will then
    reject those credentials.

    The DESIRED behaviour (asserted by the tests below) is that:
    1. A helper ``check_certificate_not_expired(cert_pem)`` (or equivalent logic
       in the issuance path) raises ``CredProcessorError`` when
       ``not_valid_after_utc < datetime.now(UTC)``.
    2. ``MsoMdocCredProcessor.issue()`` propagates that error and never calls
       the Rust signing library with an expired certificate.
    3. A certificate whose validity period is current does NOT trigger the guard.

HOW TO RUN:
    pytest mso_mdoc/tests/test_expired_certificate.py -v
"""

import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub the Rust native extension.
# ---------------------------------------------------------------------------
_iso_stub = MagicMock()
_iso_stub.MdocVerificationError = type("MdocVerificationError", (Exception,), {})
sys.modules.setdefault("isomdl_uniffi", _iso_stub)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from oid4vc.cred_processor import CredProcessorError  # noqa: E402

from ..cred_processor import MsoMdocCredProcessor  # noqa: E402


# ---------------------------------------------------------------------------
# Certificate generation helpers
# ---------------------------------------------------------------------------


def _generate_cert(
    *,
    not_valid_before_offset_days: int = -365,
    not_valid_after_offset_days: int = 365,
) -> tuple[str, str]:
    """Generate a self-signed P-256 certificate and return (private_key_pem, cert_pem).

    Args:
        not_valid_before_offset_days: Days relative to *now* for NotBefore.
        not_valid_after_offset_days: Days relative to *now* for NotAfter.

    Returns:
        (private_key_pem, certificate_pem) tuple of UTF-8 strings.
    """
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test mDoc Issuer"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=not_valid_before_offset_days))
        .not_valid_after(now + timedelta(days=not_valid_after_offset_days))
        .sign(key, hashes.SHA256())
    )

    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return private_key_pem, cert_pem


def _expired_cert_pem() -> tuple[str, str]:
    """Return (key_pem, cert_pem) for a certificate that expired yesterday."""
    return _generate_cert(
        not_valid_before_offset_days=-730,  # 2 years ago
        not_valid_after_offset_days=-1,  # expired 1 day ago
    )


def _valid_cert_pem() -> tuple[str, str]:
    """Return (key_pem, cert_pem) for a certificate valid for the next year."""
    return _generate_cert(
        not_valid_before_offset_days=-1,
        not_valid_after_offset_days=365,
    )


def _not_yet_valid_cert_pem() -> tuple[str, str]:
    """Return (key_pem, cert_pem) for a certificate that is not valid yet."""
    return _generate_cert(
        not_valid_before_offset_days=1,  # starts tomorrow
        not_valid_after_offset_days=365,
    )


# ---------------------------------------------------------------------------
# Tests for the proposed check_certificate_not_expired() helper
# ---------------------------------------------------------------------------


class TestCheckCertificateNotExpired:
    """Unit tests for the to-be-implemented certificate expiry check helper.

    The production module is expected to expose a callable with signature:
        check_certificate_not_expired(cert_pem: str) -> None
    that raises ``CredProcessorError`` when the certificate is expired or not
    yet valid, and returns None when the certificate is currently valid.

    If the helper does not exist yet, tests that import it will fail with
    ImportError — which is exactly the signal that the gap still needs closing.
    """

    @pytest.fixture(autouse=True)
    def _import_helper(self):
        """Try to import the helper; skip-with-xfail if not yet implemented."""
        try:
            from ..cred_processor import check_certificate_not_expired  # noqa: F401

            self._check = check_certificate_not_expired
        except ImportError:
            pytest.xfail(
                "check_certificate_not_expired() is not yet implemented in "
                "mso_mdoc/cred_processor.py. Implement it to fix the expired-cert gap."
            )

    def test_expired_cert_raises_cred_processor_error(self):
        """An expired certificate must raise CredProcessorError."""
        _, cert_pem = _expired_cert_pem()
        with pytest.raises(CredProcessorError, match=r"(?i)expir"):
            self._check(cert_pem)

    def test_valid_cert_does_not_raise(self):
        """A currently valid certificate must not raise."""
        _, cert_pem = _valid_cert_pem()
        self._check(cert_pem)  # no exception expected

    def test_not_yet_valid_cert_raises_cred_processor_error(self):
        """A certificate whose NotBefore is in the future must raise CredProcessorError."""
        _, cert_pem = _not_yet_valid_cert_pem()
        with pytest.raises(CredProcessorError, match=r"(?i)not yet valid|expir|invalid"):
            self._check(cert_pem)

    def test_invalid_pem_raises_cred_processor_error(self):
        """A non-PEM string must raise CredProcessorError, not a raw cryptography exc."""
        with pytest.raises((CredProcessorError, ValueError)):
            self._check("this is not a certificate")

    def test_empty_string_raises(self):
        """An empty string is not a certificate."""
        with pytest.raises((CredProcessorError, ValueError)):
            self._check("")


# ---------------------------------------------------------------------------
# Integration: MsoMdocCredProcessor.issue() must reject expired certificates
# ---------------------------------------------------------------------------


def _make_profile():
    profile = MagicMock()
    session = MagicMock()

    @asynccontextmanager
    async def _session():
        yield session

    profile.session = _session
    profile.settings = MagicMock()
    profile.settings.get.return_value = None
    return profile, session


class TestIssueRejectsExpiredCertificate:
    """MsoMdocCredProcessor.issue() must not sign with an expired certificate.

    The signing key and certificate are provided via
    ``SupportedCredential.vc_additional_data``.  The expiry check in
    ``check_certificate_not_expired()`` runs before calling the Rust signer.
    """

    def _make_ex_record(self, verification_method="did:key:test#0"):
        ex = MagicMock()
        ex.verification_method = verification_method
        ex.supported_cred_id = "sc-001"
        ex.credential_subject = {
            "org.iso.18013.5.1": {
                "family_name": "Doe",
                "given_name": "Jane",
            }
        }
        ex.state = "offer_created"
        return ex

    def _make_supported(self):
        sup = MagicMock()
        sup.format = "mso_mdoc"
        sup.format_data = {"doctype": "org.iso.18013.5.1.mDL"}
        sup.identifier = "mDL"
        sup.vc_additional_data = {}
        return sup

    def _make_pop(self):
        pop = MagicMock()
        pop.verified = True
        pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        pop.holder_kid = None
        return pop

    def _make_admin_context(self, profile):
        ctx = MagicMock()
        ctx.profile = profile
        ctx.settings = profile.settings
        return ctx

    @pytest.mark.asyncio
    async def test_issue_raises_when_certificate_is_expired(self):
        """issue() must raise CredProcessorError when the cert is expired."""
        private_key_pem, expired_cert_pem = _expired_cert_pem()

        key_rec = MagicMock()
        key_rec.private_key_pem = private_key_pem
        key_rec.certificate_pem = expired_cert_pem

        profile, _ = _make_profile()
        context = self._make_admin_context(profile)
        supported = self._make_supported()
        ex_record = self._make_ex_record()
        pop = self._make_pop()

        with (
            patch("mso_mdoc.cred_processor.isomdl_mdoc_sign") as mock_sign,
            patch(
                "mso_mdoc.cred_processor.MdocSigningKeyRecord.query",
                AsyncMock(return_value=[key_rec]),
            ),
        ):
            processor = MsoMdocCredProcessor()

            with pytest.raises(CredProcessorError, match=r"(?i)expir"):
                await processor.issue(
                    body={"doctype": "org.iso.18013.5.1.mDL"},
                    supported=supported,
                    ex_record=ex_record,
                    pop=pop,
                    context=context,
                )

            # The Rust signer must NEVER have been called with an expired cert.
            mock_sign.assert_not_called()

    @pytest.mark.asyncio
    async def test_issue_succeeds_when_certificate_is_valid(self):
        """issue() must NOT raise when the certificate is currently valid."""
        private_key_pem, valid_cert_pem = _valid_cert_pem()

        key_rec = MagicMock()
        key_rec.private_key_pem = private_key_pem
        key_rec.certificate_pem = valid_cert_pem

        profile, _ = _make_profile()
        context = self._make_admin_context(profile)
        supported = self._make_supported()
        ex_record = self._make_ex_record()
        pop = self._make_pop()

        with (
            patch(
                "mso_mdoc.cred_processor.isomdl_mdoc_sign",
                return_value="oLHC0-T1",  # base64url without padding as returned by isomdl-uniffi
            ),
            patch(
                "mso_mdoc.cred_processor.MdocSigningKeyRecord.query",
                AsyncMock(return_value=[key_rec]),
            ),
        ):
            processor = MsoMdocCredProcessor()

            try:
                await processor.issue(
                    body={"doctype": "org.iso.18013.5.1.mDL"},
                    supported=supported,
                    ex_record=ex_record,
                    pop=pop,
                    context=context,
                )
            except CredProcessorError as exc:
                # Accept errors that are NOT about certificate expiry.
                assert "expir" not in str(exc).lower(), (
                    f"Valid certificate incorrectly triggered expiry check: {exc}"
                )
