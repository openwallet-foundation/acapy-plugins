"""Example mDOC credential flow test.

This is a reference implementation showing mDOC test patterns.
Use this as a template when migrating or writing mDOC tests.
"""

import pytest

from tests.base import BaseMdocTest
from tests.helpers import MDL_MANDATORY_FIELDS, Doctype, assert_presentation_successful


class TestMdocFlow(BaseMdocTest):
    """Example test class demonstrating mDOC flow patterns."""

    @pytest.mark.asyncio
    async def test_issue_and_verify_mdl(
        self,
        credential_flow,
        presentation_flow,
        issuer_did,
        setup_all_trust_anchors,
    ):
        """Test issuing and verifying an mDL (mobile driver's license).

        This test demonstrates:
        1. Using BaseMdocTest (automatically uses P-256 issuer_did)
        2. PKI trust anchor setup via fixture
        3. Using credential_flow for mDOC issuance
        4. Using presentation_flow for mDOC verification
        """
        # Note: issuer_did is automatically P-256 for mDOC tests
        # Trust anchors are set up via setup_all_trust_anchors fixture

        # Issue mDL credential
        result = await credential_flow.issue_mdoc(
            doctype=Doctype.MDL,
            claims_config={
                Doctype.MDL_NAMESPACE: {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                    "issue_date": {"mandatory": True},
                    "expiry_date": {"mandatory": True},
                    "issuing_country": {"mandatory": True},
                    "issuing_authority": {"mandatory": True},
                    "document_number": {"mandatory": True},
                }
            },
            credential_subject={
                Doctype.MDL_NAMESPACE: {
                    "given_name": "Alice",
                    "family_name": "Smith",
                    "birth_date": "1990-01-01",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2033-01-01",
                    "issuing_country": "US",
                    "issuing_authority": "DMV",
                    "document_number": "D1234567",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            issuer_did=issuer_did,
        )

        # Validate mDOC structure
        assert result["credential"]
        assert result["exchange_id"]

        # Verify presentation
        verification = await presentation_flow.verify_mdoc(
            credential=result["credential"],
            doctype=Doctype.MDL,
            required_claims=["given_name", "family_name", "birth_date"],
            namespace=Doctype.MDL_NAMESPACE,
        )

        # Assert presentation was successful
        assert_presentation_successful(verification["presentation"])

    @pytest.mark.asyncio
    async def test_mdoc_selective_disclosure(
        self,
        credential_flow,
        presentation_flow,
        issuer_did,
        setup_all_trust_anchors,
    ):
        """Test mDOC with selective disclosure of claims."""
        # Issue full mDL
        result = await credential_flow.issue_mdoc(
            doctype=Doctype.MDL,
            claims_config={
                Doctype.MDL_NAMESPACE: {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                    "address": {"mandatory": False},
                }
            },
            credential_subject={
                Doctype.MDL_NAMESPACE: {
                    "given_name": "Alice",
                    "family_name": "Smith",
                    "birth_date": "1990-01-01",
                    "address": "123 Main St, Springfield, 12345",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            issuer_did=issuer_did,
        )

        # Verify with only name claims (NOT address)
        verification = await presentation_flow.verify_mdoc(
            credential=result["credential"],
            doctype=Doctype.MDL,
            required_claims=["given_name", "family_name"],
            namespace=Doctype.MDL_NAMESPACE,
        )

        # Address should NOT be disclosed
        matched_creds = verification["matched_credentials"]
        query_id = list(matched_creds.keys())[0]
        disclosed_data = matched_creds[query_id]

        # Check that only requested claims are present
        assert "given_name" in str(disclosed_data) or "Alice" in str(disclosed_data)
        assert "family_name" in str(disclosed_data) or "Smith" in str(disclosed_data)
        # Address should NOT be disclosed
        assert "123 Main St" not in str(disclosed_data)


class TestMdocAgePredicates(BaseMdocTest):
    """Test mDOC age over predicates (age_over_18, age_over_21, etc.)."""

    @pytest.mark.asyncio
    async def test_age_over_18_without_revealing_birthdate(
        self,
        credential_flow,
        presentation_flow,
        issuer_did,
        setup_all_trust_anchors,
    ):
        """Test age verification without revealing exact birth date."""
        # Issue mDL with birth date
        result = await credential_flow.issue_mdoc(
            doctype=Doctype.MDL,
            claims_config={
                Doctype.MDL_NAMESPACE: {
                    "given_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                    "age_over_18": {"mandatory": True, "value_type": "boolean"},
                    "age_over_21": {"mandatory": True, "value_type": "boolean"},
                }
            },
            credential_subject={
                Doctype.MDL_NAMESPACE: {
                    "family_name": "Smith",
                    "given_name": "Alice",
                    "birth_date": "1990-01-01",
                    "age_over_18": True,
                    "age_over_21": True,
                    **MDL_MANDATORY_FIELDS,
                }
            },
            issuer_did=issuer_did,
        )

        # Verify age_over_18 WITHOUT requesting birth_date
        verification = await presentation_flow.verify_mdoc(
            credential=result["credential"],
            doctype=Doctype.MDL,
            required_claims=["age_over_18"],  # NOT birth_date
            namespace=Doctype.MDL_NAMESPACE,
        )

        matched_creds = verification["matched_credentials"]
        query_id = list(matched_creds.keys())[0]
        disclosed_data = matched_creds[query_id]

        # age_over_18 should be present
        assert (
            "age_over_18" in str(disclosed_data)
            or "true" in str(disclosed_data).lower()
        )

        # birth_date should NOT be disclosed
        assert "1990-01-01" not in str(disclosed_data)
        assert "birth_date" not in str(disclosed_data)
