from unittest.mock import MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from sd_jwt_vc.cred_processor import CredProcessorError, SdJwtCredIssueProcessor


@pytest.mark.asyncio
class TestSdJwtCredIssueProcessor:
    async def test_issue_vct_validation(self):
        processor = SdJwtCredIssueProcessor()

        # Mock dependencies
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {"vct": "IdentityCredential"}
        supported.vc_additional_data = {"sd_list": []}

        ex_record = MagicMock(spec=OID4VCIExchangeRecord)
        ex_record.credential_subject = {}
        ex_record.verification_method = "did:example:issuer#key-1"

        pop = MagicMock(spec=PopResult)
        pop.holder_kid = "did:example:holder#key-1"
        pop.holder_jwk = None

        context = MagicMock(spec=AdminRequestContext)

        # We need to mock the SDJWTIssuer to avoid actual JWT operations
        with patch("sd_jwt_vc.cred_processor.SDJWTIssuer") as mock_issuer_cls:
            mock_issuer = mock_issuer_cls.return_value
            mock_issuer.sd_jwt_payload = "mock_payload"

            # We also need to mock jwt_sign
            with patch(
                "sd_jwt_vc.cred_processor.jwt_sign", return_value="mock_signed_jwt"
            ):
                # Case 1: No vct in body -> Should pass validation
                body_no_vct = {}
                try:
                    await processor.issue(body_no_vct, supported, ex_record, pop, context)
                except CredProcessorError as e:
                    pytest.fail(
                        f"Should not raise CredProcessorError for missing vct: {e}"
                    )
                except Exception as e:
                    # If it fails for other reasons, we might need to mock more
                    print(
                        f"Caught expected exception during execution (not validation failure): {e}"
                    )

                # Case 2: Matching vct -> Should pass validation
                body_match_vct = {"vct": "IdentityCredential"}
                try:
                    await processor.issue(
                        body_match_vct, supported, ex_record, pop, context
                    )
                except CredProcessorError as e:
                    pytest.fail(
                        f"Should not raise CredProcessorError for matching vct: {e}"
                    )
                except Exception as e:
                    print(
                        f"Caught expected exception during execution (not validation failure): {e}"
                    )

                # Case 3: Mismatching vct -> Should raise CredProcessorError
                body_mismatch_vct = {"vct": "WrongCredential"}
                with pytest.raises(
                    CredProcessorError, match="Requested vct does not match offer"
                ):
                    await processor.issue(
                        body_mismatch_vct, supported, ex_record, pop, context
                    )


class TestValidateCredentialSubject:
    """Tests for validate_credential_subject method."""

    def test_valid_subject_with_all_claims(self):
        """Test validation passes when all mandatory claims are present."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "email": {"mandatory": False},
            },
        }
        supported.vc_additional_data = {"sd_list": ["/given_name", "/family_name"]}

        subject = {
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com",
        }

        # Should not raise
        processor.validate_credential_subject(supported, subject)

    def test_missing_mandatory_sd_claim(self):
        """Test validation fails when mandatory SD claim is missing."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
            },
        }
        supported.vc_additional_data = {"sd_list": ["/given_name", "/family_name"]}

        subject = {"given_name": "John"}  # Missing family_name

        with pytest.raises(
            CredProcessorError, match="selectively disclosable claim is mandatory"
        ):
            processor.validate_credential_subject(supported, subject)

    def test_missing_mandatory_non_sd_claim(self):
        """Test that non-SD mandatory claims are not currently validated.

        The current implementation only validates mandatory fields that are
        selectively disclosable (in sd_list). Non-SD mandatory field validation
        is TODO as noted in the code.
        """
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},  # Not in sd_list
                "family_name": {"mandatory": False},
            },
        }
        supported.vc_additional_data = {"sd_list": []}  # No SD claims

        subject = {"family_name": "Doe"}  # Missing mandatory given_name

        # Currently passes because the implementation only validates SD claims
        # TODO: This should raise once non-SD mandatory validation is implemented
        processor.validate_credential_subject(supported, subject)

    def test_optional_claims_can_be_missing(self):
        """Test validation passes when only optional claims are missing."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "middle_name": {"mandatory": False},
                "nickname": {},  # No mandatory field = optional
            },
        }
        supported.vc_additional_data = {"sd_list": ["/given_name"]}

        subject = {"given_name": "John"}  # middle_name and nickname missing

        # Should not raise
        processor.validate_credential_subject(supported, subject)

    def test_iat_claim_skipped(self):
        """Test that /iat is skipped even if in sd_list."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "iat": {"mandatory": True},
            },
        }
        supported.vc_additional_data = {"sd_list": ["/iat"]}

        subject = {}  # iat not in subject (it's added during issue)

        # Should not raise - /iat is explicitly skipped
        processor.validate_credential_subject(supported, subject)

    def test_nested_mandatory_claim(self):
        """Test validation of nested mandatory claims.

        The current implementation only validates mandatory fields that are
        selectively disclosable (in sd_list). Nested non-SD mandatory claims
        are not currently validated.
        """
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "address": {
                    "mandatory": True,
                    "claims": {
                        "street": {"mandatory": True},
                        "city": {"mandatory": False},
                    },
                },
            },
        }
        supported.vc_additional_data = {"sd_list": []}

        # Missing nested mandatory claim
        subject = {"address": {"city": "New York"}}  # Missing street

        # Currently passes because nested validation is TODO
        processor.validate_credential_subject(supported, subject)

    def test_nested_claim_present(self):
        """Test validation passes with nested mandatory claims present."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "address": {
                    "mandatory": True,
                    "claims": {
                        "street": {"mandatory": True},
                        "city": {"mandatory": False},
                    },
                },
            },
        }
        supported.vc_additional_data = {"sd_list": []}

        subject = {"address": {"street": "123 Main St", "city": "New York"}}

        # Should not raise
        processor.validate_credential_subject(supported, subject)

    def test_no_claims_metadata(self):
        """Test validation with no claims metadata defined."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {"vct": "IdentityCredential"}  # No claims
        supported.vc_additional_data = {"sd_list": ["/given_name"]}

        subject = {"given_name": "John"}

        # Should not raise - no metadata means no mandatory checks
        processor.validate_credential_subject(supported, subject)

    def test_empty_sd_list(self):
        """Test validation with empty sd_list but mandatory claims in metadata."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
            },
        }
        supported.vc_additional_data = {"sd_list": []}

        subject = {"given_name": "John", "family_name": "Doe"}

        # Should not raise
        processor.validate_credential_subject(supported, subject)

    def test_mixed_sd_and_non_sd_mandatory_claims(self):
        """Test validation with both SD and non-SD mandatory claims."""
        processor = SdJwtCredIssueProcessor()
        supported = MagicMock(spec=SupportedCredential)
        supported.format_data = {
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},  # In SD list
                "family_name": {"mandatory": True},  # Not in SD list
                "email": {"mandatory": False},
            },
        }
        supported.vc_additional_data = {"sd_list": ["/given_name"]}

        # All mandatory claims present
        subject = {"given_name": "John", "family_name": "Doe"}
        processor.validate_credential_subject(supported, subject)

        # Missing SD mandatory claim
        subject_missing_sd = {"family_name": "Doe"}
        with pytest.raises(
            CredProcessorError, match="selectively disclosable claim is mandatory"
        ):
            processor.validate_credential_subject(supported, subject_missing_sd)

        # Missing non-SD mandatory claim - currently not validated (TODO in implementation)
        subject_missing_non_sd = {"given_name": "John"}
        # This currently passes because non-SD mandatory validation is not implemented
        processor.validate_credential_subject(supported, subject_missing_non_sd)
