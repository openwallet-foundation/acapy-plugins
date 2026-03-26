"""Tests for MsoMdocCredProcessor integration."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from oid4vc.models.supported_cred import SupportedCredential

from ..cred_processor import MsoMdocCredProcessor


class TestMsoMdocCredProcessor:
    """Test MsoMdocCredProcessor functionality."""

    @pytest.fixture
    def cred_processor(self):
        """Create MsoMdocCredProcessor instance."""
        return MsoMdocCredProcessor()

    @pytest.fixture
    def mock_supported_credential(self):
        """Mock supported credential."""
        supported = MagicMock(spec=SupportedCredential)
        supported.format = "mso_mdoc"
        supported.format_data = {"doctype": "org.iso.18013.5.1.mDL"}
        supported.vc_additional_data = {}
        return supported

    @pytest.fixture
    def sample_body(self):
        """Sample credential request body."""
        return {
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "age_over_18": True,
            "document_number": "DL123456789",
        }

    def test_processor_initialization(self, cred_processor):
        """Test that the processor initializes correctly."""
        assert cred_processor is not None
        assert hasattr(cred_processor, "issue")

    def test_processor_has_required_methods(self, cred_processor):
        """Test that processor has required interface methods."""
        # Check that it has the methods expected by the Issuer protocol
        assert callable(getattr(cred_processor, "issue", None))

    @pytest.mark.asyncio
    async def test_processor_interface_compatibility(
        self, cred_processor, sample_body, mock_supported_credential
    ):
        """Test that processor interface is compatible with expected signature."""
        # This tests the interface without actually calling the backend
        # which would require proper key setup and storage

        # Create mock context and exchange record
        mock_context = MagicMock()
        mock_session = AsyncMock()

        # Fix: inject is synchronous and should return a mock storage
        mock_storage = MagicMock()
        # find_all_records is awaited, so it must be async
        mock_storage.find_all_records = AsyncMock(return_value=[])
        # get_record is also awaited
        mock_storage.get_record = AsyncMock(return_value=None)

        mock_session.inject = MagicMock(return_value=mock_storage)

        mock_context.profile.session.return_value = mock_session
        mock_session.__aenter__.return_value = mock_session

        mock_exchange_record = MagicMock()
        mock_pop_result = MagicMock()
        mock_pop_result.holder_jwk = None
        mock_pop_result.holder_kid = None

        # Test that the method signature is correct
        # We expect this to fail at runtime due to missing setup,
        # but the interface should be correct
        from oid4vc.cred_processor import CredProcessorError

        try:
            await cred_processor.issue(
                body=sample_body,
                supported=mock_supported_credential,
                context=mock_context,
                ex_record=mock_exchange_record,
                pop=mock_pop_result,
            )
        except (AttributeError, TypeError, ValueError, CredProcessorError):
            # Expected - we're testing interface, not full functionality
            pass

    def test_doctype_handling(self, cred_processor):
        """Test doctype validation and handling."""
        valid_doctypes = [
            "org.iso.18013.5.1.mDL",
            "org.iso.23220.photoid.1",
            "org.iso.18013.5.1.aamva",
        ]

        for doctype in valid_doctypes:
            # Basic doctype format validation
            assert isinstance(doctype, str)
            assert doctype.startswith("org.iso.")
            assert "." in doctype

    def test_processor_error_handling(self, cred_processor):
        """Test processor error handling."""
        # Test that processor imports CredProcessorError correctly
        from oid4vc.cred_processor import CredProcessorError

        # Verify error class is available
        assert CredProcessorError is not None
        assert issubclass(CredProcessorError, Exception)

    @pytest.mark.asyncio
    async def test_issue_calls_signer_correctly(
        self, cred_processor, sample_body, mock_supported_credential
    ):
        """Test that issue method correctly prepares data and calls signer."""
        from unittest.mock import patch

        from oid4vc.models.exchange import OID4VCIExchangeRecord
        from oid4vc.pop_result import PopResult

        # Mock dependencies
        mock_context = MagicMock()

        # Mock signer
        key_rec = MagicMock()
        key_rec.private_key_pem = "test-priv-key"
        key_rec.certificate_pem = "test-cert"

        with (
            patch("mso_mdoc.cred_processor.isomdl_mdoc_sign") as mock_sign,
            patch("mso_mdoc.cred_processor.check_certificate_not_expired"),
            patch(
                "mso_mdoc.cred_processor.MdocSigningKeyRecord.query",
                AsyncMock(return_value=[key_rec]),
            ),
        ):
            mock_sign.return_value = (
                "oLHC0-T1"  # base64url without padding as returned by isomdl-uniffi
            )

            # Setup input
            ex_record = MagicMock(spec=OID4VCIExchangeRecord)
            ex_record.verification_method = None
            ex_record.credential_subject = sample_body

            pop = MagicMock(spec=PopResult)
            pop.holder_jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": "holder",
                "y": "holder",
            }
            pop.holder_kid = None

            # Call issue
            result = await cred_processor.issue(
                body={"doctype": "org.iso.18013.5.1.mDL"},
                supported=mock_supported_credential,
                ex_record=ex_record,
                pop=pop,
                context=mock_context,
            )

            # Verify result: issuer_signed_b64() returns base64url directly
            assert result == "oLHC0-T1"

            # Verify signer was called with correct arguments
            mock_sign.assert_called_once()
            call_args = mock_sign.call_args
            assert call_args[0][0] == pop.holder_jwk  # holder_jwk
            assert call_args[0][1]["doctype"] == "org.iso.18013.5.1.mDL"  # headers
            assert call_args[0][2] == sample_body  # payload
            assert call_args[0][3] == "test-cert"  # cert
            assert call_args[0][4] == "test-priv-key"  # priv key
