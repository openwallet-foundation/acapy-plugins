"""Tests for MsoMdocCredProcessor validation."""

from unittest.mock import MagicMock

import pytest

from oid4vc.cred_processor import CredProcessorError
from oid4vc.models.supported_cred import SupportedCredential

from ..cred_processor import MsoMdocCredProcessor


class TestMsoMdocValidation:
    """Test MsoMdocCredProcessor validations."""

    @pytest.fixture
    def cred_processor(self):
        """Create MsoMdocCredProcessor instance."""
        return MsoMdocCredProcessor()

    def test_validate_credential_subject_invalid(self, cred_processor):
        """Test that validate_credential_subject rejects invalid data."""
        supported = MagicMock(spec=SupportedCredential)

        # Invalid subject (empty)
        invalid_subject = {}

        # Should raise an error
        with pytest.raises(CredProcessorError):
            cred_processor.validate_credential_subject(supported, invalid_subject)

    def test_validate_supported_credential_invalid(self, cred_processor):
        """Test that validate_supported_credential rejects invalid data."""
        # Invalid supported credential (empty format_data)
        invalid_supported = MagicMock(spec=SupportedCredential)
        invalid_supported.format_data = {}

        # Should raise an error
        with pytest.raises(CredProcessorError):
            cred_processor.validate_supported_credential(invalid_supported)
