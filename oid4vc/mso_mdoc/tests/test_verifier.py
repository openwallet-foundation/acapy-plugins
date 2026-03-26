"""Tests for MsoMdoc Verifier implementation."""

import sys
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest

from oid4vc.models.presentation import OID4VPPresentation

from ..mdoc.cred_verifier import MsoMdocCredVerifier, PreverifiedMdocClaims
from ..mdoc.pres_verifier import MsoMdocPresVerifier
from oid4vc.cred_processor import VerifyResult

# Mock acapy_agent and dependencies before importing module under test
sys.modules["pydid"] = MagicMock()
sys.modules["acapy_agent"] = MagicMock()
sys.modules["acapy_agent.core"] = MagicMock()
sys.modules["acapy_agent.core.profile"] = MagicMock()

# Mock isomdl_uniffi since it's a native extension
sys.modules["isomdl_uniffi"] = MagicMock()


@pytest.fixture(autouse=True)
def mock_isomdl_module():
    """Mock isomdl_uniffi module."""
    # It's already mocked in sys.modules, but we can yield it for configuration
    return sys.modules["isomdl_uniffi"]


def create_mock_profile_with_session():
    """Create a mock profile with properly mocked async session context manager."""
    profile = MagicMock()
    mock_session = MagicMock()

    @asynccontextmanager
    async def mock_session_context():
        yield mock_session

    profile.session = mock_session_context
    profile.settings = MagicMock()
    profile.settings.get = MagicMock(return_value=None)
    return profile, mock_session


class TestMsoMdocCredVerifier:
    """Test MsoMdocCredVerifier functionality."""

    @pytest.mark.asyncio
    async def test_verify_credential_stub(self):
        """Test the stub implementation of verify_credential.

        A trust store with at least one anchor is required; without one the
        fail-closed guard returns verified=False before calling isomdl.
        """
        pem_cert = (
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----\n"
        )

        verifier = MsoMdocCredVerifier(trust_anchors=[pem_cert])
        profile = MagicMock()

        # Patch isomdl_uniffi in the verifier module
        with patch("mso_mdoc.mdoc.cred_verifier.isomdl_uniffi") as mock_isomdl:
            # Create a real exception class for MdocVerificationError
            class MockMdocVerificationError(Exception):
                pass

            mock_isomdl.MdocVerificationError = MockMdocVerificationError

            # Use a simple class instead of MagicMock to ensure JSON serializable values
            class MockVerificationResult:
                verified = True
                common_name = "Test Issuer"
                error = None

            class MockMdoc:
                def doctype(self):
                    return "org.iso.18013.5.1.mDL"

                def id(self):
                    return "test-id-12345"

                def details(self):
                    return {}

                def verify_issuer_signature(self, trust_anchors, enable_chaining):
                    return MockVerificationResult()

            mock_isomdl.Mdoc.from_string.return_value = MockMdoc()

            # Use a hex-encoded credential string to go through the hex parsing path
            # The credential must be all hex characters (0-9, a-f, A-F)
            hex_credential = "a0b1c2d3e4f5"

            result = await verifier.verify_credential(profile, hex_credential)

            assert isinstance(result, VerifyResult)
            assert result.verified is True
            assert result.payload["status"] == "verified"
            assert result.payload["doctype"] == "org.iso.18013.5.1.mDL"
            mock_isomdl.Mdoc.from_string.assert_called_once_with(hex_credential)


class TestMsoMdocPresVerifier:
    """Test MsoMdocPresVerifier functionality."""

    @pytest.fixture
    def verifier(self):
        """Create verifier instance with a minimal trust store.

        A non-empty trust store is required because verify_presentation is
        fail-closed: it returns verified=False immediately when no trust
        anchors are configured, before reaching any Rust verification call.
        """
        pem_cert = (
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----\n"
        )

        return MsoMdocPresVerifier(trust_anchors=[pem_cert])

    @pytest.fixture
    def mock_presentation(self):
        """Create mock presentation."""
        pres = MagicMock(spec=OID4VPPresentation)
        pres.verifiable_presentation = "base64_encoded_vp"
        pres.pres_def_id = "mock_pres_def_id"
        pres.presentation_submission = MagicMock()
        pres.presentation_submission.descriptor_map = [
            MagicMock(path="$.vp_token", format="mso_mdoc")
        ]
        pres.nonce = "test_nonce"
        return pres

    @pytest.mark.asyncio
    async def test_verify_presentation_success(self, verifier, mock_presentation):
        """Test successful presentation verification."""
        profile, mock_session = create_mock_profile_with_session()
        presentation_data = "mock_presentation_data"

        with (
            patch("mso_mdoc.mdoc.pres_verifier.isomdl_uniffi") as mock_isomdl,
            patch("mso_mdoc.mdoc.pres_verifier.Config") as mock_config,
            patch(
                "mso_mdoc.mdoc.pres_verifier.retrieve_or_create_did_jwk"
            ) as mock_did_jwk,
        ):
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            # Mock the DID JWK retrieval as async
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_did_jwk.return_value = mock_jwk

            # Setup Enum constants
            mock_isomdl.AuthenticationStatus.VALID = "VALID"

            # Mock verify_oid4vp_response result - all values must be JSON serializable
            mock_response_data = MagicMock()
            mock_response_data.issuer_authentication = "VALID"
            mock_response_data.device_authentication = "VALID"
            mock_response_data.errors = []
            mock_response_data.doc_type = "org.iso.18013.5.1.mDL"
            # verified_response is now a dict structure used by extract_verified_claims
            mock_response_data.verified_response = {}

            mock_isomdl.verify_oid4vp_response.return_value = mock_response_data

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert isinstance(result, VerifyResult)
            assert result.verified is True
            assert isinstance(result.payload, PreverifiedMdocClaims)
            assert result.payload.claims["status"] == "verified"
            assert result.payload.claims["docType"] == "org.iso.18013.5.1.mDL"

            mock_isomdl.verify_oid4vp_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_presentation_failure(self, verifier, mock_presentation):
        """Test failed presentation verification."""
        profile, mock_session = create_mock_profile_with_session()
        presentation_data = "mock_presentation_data"

        with (
            patch("mso_mdoc.mdoc.pres_verifier.isomdl_uniffi") as mock_isomdl,
            patch("mso_mdoc.mdoc.pres_verifier.Config") as mock_config,
            patch(
                "mso_mdoc.mdoc.pres_verifier.retrieve_or_create_did_jwk"
            ) as mock_did_jwk,
        ):
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            # Mock the DID JWK retrieval
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_did_jwk.return_value = mock_jwk

            # Setup Enum constants
            mock_isomdl.AuthenticationStatus.VALID = "VALID"
            mock_isomdl.AuthenticationStatus.INVALID = "INVALID"

            # Mock verify_oid4vp_response failure
            mock_response_data = MagicMock()
            mock_response_data.issuer_authentication = "INVALID"
            mock_response_data.device_authentication = "VALID"
            mock_response_data.errors = ["Issuer auth failed"]
            mock_response_data.doc_type = "org.iso.18013.5.1.mDL"
            mock_response_data.verified_response_as_json.return_value = {}

            mock_isomdl.verify_oid4vp_response.return_value = mock_response_data

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert result.verified is False
            assert "Issuer auth failed" in result.payload["error"]

    @pytest.mark.asyncio
    async def test_verify_presentation_exception(self, verifier, mock_presentation):
        """Test exception handling during verification."""
        profile, mock_session = create_mock_profile_with_session()
        presentation_data = "mock_presentation_data"

        with (
            patch("mso_mdoc.mdoc.pres_verifier.isomdl_uniffi") as mock_isomdl,
            patch("mso_mdoc.mdoc.pres_verifier.Config") as mock_config,
            patch(
                "mso_mdoc.mdoc.pres_verifier.retrieve_or_create_did_jwk"
            ) as mock_did_jwk,
        ):
            mock_config.from_settings.return_value.endpoint = "http://test-endpoint"

            # Mock the DID JWK retrieval
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:test"
            mock_did_jwk.return_value = mock_jwk

            mock_isomdl.verify_oid4vp_response.side_effect = Exception("Native error")

            result = await verifier.verify_presentation(
                profile, presentation_data, mock_presentation
            )

            assert result.verified is False
            assert "Native error" in str(result.payload["error"])
