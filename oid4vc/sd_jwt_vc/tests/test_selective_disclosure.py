"""Tests for selective disclosure functionality in SD-JWT credentials."""

from unittest.mock import MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor


@pytest.mark.asyncio
class TestSelectiveDisclosure:
    """Test selective disclosure features in SD-JWT credentials."""

    async def test_sd_list_basic(self):
        """Test basic selective disclosure with sd_list."""
        processor = SdJwtCredIssueProcessor()

        # Define a credential with selective disclosure
        supported = MagicMock(spec=SupportedCredential)
        supported.format = "vc+sd-jwt"
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "email": {"mandatory": False},
                "phone": {"mandatory": False},
            },
        }
        # Only email and phone are selectively disclosable
        supported.vc_additional_data = {"sd_list": ["/email", "/phone"]}

        ex_record = MagicMock(spec=OID4VCIExchangeRecord)
        ex_record.issuer_id = "did:example:issuer"
        ex_record.credential_subject = {
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com",
            "phone": "+1-555-0100",
        }
        ex_record.verification_method = "did:example:issuer#key-1"

        pop = MagicMock(spec=PopResult)
        pop.holder_kid = "did:example:holder#key-1"
        pop.holder_jwk = None

        context = MagicMock(spec=AdminRequestContext)
        context.inject_or.return_value = None

        with patch("sd_jwt_vc.cred_processor.sd_jwt_sign", return_value="mock_jwt"):
            result = await processor.issue({}, supported, ex_record, pop, context)

            # Verify sd_jwt_sign was called

    async def test_nested_selective_disclosure(self):
        """Test selective disclosure with nested claims."""
        processor = SdJwtCredIssueProcessor()

        supported = MagicMock(spec=SupportedCredential)
        supported.format = "vc+sd-jwt"
        supported.format_data = {
            "vct": "AddressCredential",
            "claims": {
                "address": {
                    "mandatory": True,
                    "claims": {
                        "street": {"mandatory": True},
                        "city": {"mandatory": True},
                        "postal_code": {"mandatory": False},
                        "country": {"mandatory": False},
                    },
                },
            },
        }
        # Make specific nested fields selectively disclosable
        supported.vc_additional_data = {
            "sd_list": ["/address/postal_code", "/address/country"]
        }

        ex_record = MagicMock(spec=OID4VCIExchangeRecord)
        ex_record.issuer_id = "did:example:issuer"
        ex_record.credential_subject = {
            "address": {
                "street": "123 Main St",
                "city": "Springfield",
                "postal_code": "12345",
                "country": "US",
            }
        }
        ex_record.verification_method = "did:example:issuer#key-1"

        pop = MagicMock(spec=PopResult)
        pop.holder_kid = "did:example:holder#key-1"
        pop.holder_jwk = None

        context = MagicMock(spec=AdminRequestContext)
        context.inject_or.return_value = None

        with patch("sd_jwt_vc.cred_processor.sd_jwt_sign", return_value="mock_jwt"):
            result = await processor.issue({}, supported, ex_record, pop, context)

            # Verify sd_jwt_sign was called
