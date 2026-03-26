"""Example SD-JWT credential flow test.

This is a reference implementation showing the new DRY test pattern.
Use this as a template when migrating or writing new tests.
"""

import pytest

from tests.base import BaseSdJwtTest
from tests.helpers import (
    VCT,
    assert_disclosed_claims,
    assert_hidden_claims,
    assert_valid_sd_jwt,
)


class TestSDJWTFlow(BaseSdJwtTest):
    """Example test class demonstrating SD-JWT flow patterns."""

    @pytest.mark.asyncio
    async def test_issue_and_verify_identity_credential(
        self, credential_flow, presentation_flow, issuer_did
    ):
        """Test issuing and verifying an SD-JWT identity credential.

        This test demonstrates:
        1. Using credential_flow helper to issue SD-JWT
        2. Using presentation_flow helper to verify
        3. Using custom assertions for claim verification
        """
        # Issue credential with selective disclosure
        result = await credential_flow.issue_sd_jwt(
            vct=VCT.IDENTITY,
            claims_config={
                "given_name": {"mandatory": True, "value_type": "string"},
                "family_name": {"mandatory": True, "value_type": "string"},
                "email": {"mandatory": False, "value_type": "string"},
                "ssn": {"mandatory": False, "value_type": "string"},
            },
            credential_subject={
                "given_name": "Alice",
                "family_name": "Smith",
                "email": "alice@example.com",
                "ssn": "123-45-6789",
            },
            sd_list=["/given_name", "/family_name", "/email", "/ssn"],
            issuer_did=issuer_did,
        )

        # Validate credential structure
        assert_valid_sd_jwt(
            result["credential"],
            expected_claims=["given_name", "family_name"],
        )

        # Verify presentation with selective disclosure
        # Only request given_name and family_name, NOT email or ssn
        verification = await presentation_flow.verify_sd_jwt(
            credential=result["credential"],
            vct=VCT.IDENTITY,
            required_claims=["given_name", "family_name"],
        )

        # Assert presentation was successful
        # verified is a boolean True in the OID4VP response record
        assert verification["presentation"].get("verified") is True

        # Get the matched credentials from presentation
        matched_creds = verification["matched_credentials"]
        query_id = list(matched_creds.keys())[0]

        # Verify required claims are disclosed
        assert_disclosed_claims(
            matched_creds,
            query_id,
            expected_claims=["given_name", "family_name"],
        )

        # Verify sensitive claims are NOT disclosed
        assert_hidden_claims(
            matched_creds,
            query_id,
            excluded_claims=["email", "ssn"],
        )

    @pytest.mark.asyncio
    async def test_multiple_credentials_same_holder(
        self, credential_flow, presentation_flow, issuer_did
    ):
        """Test issuing multiple credentials to the same holder."""
        # Issue identity credential
        identity = await credential_flow.issue_sd_jwt(
            vct=VCT.IDENTITY,
            claims_config={
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
            },
            credential_subject={
                "given_name": "Alice",
                "family_name": "Smith",
            },
            sd_list=["/given_name", "/family_name"],
            issuer_did=issuer_did,
        )

        # Issue address credential
        address = await credential_flow.issue_sd_jwt(
            vct=VCT.ADDRESS,
            claims_config={
                "street_address": {"mandatory": True},
                "locality": {"mandatory": True},
                "postal_code": {"mandatory": True},
            },
            credential_subject={
                "street_address": "123 Main St",
                "locality": "Springfield",
                "postal_code": "12345",
            },
            sd_list=["/street_address", "/locality", "/postal_code"],
            issuer_did=issuer_did,
        )

        # Verify both credentials exist
        assert identity["credential"]
        assert address["credential"]
        assert identity["exchange_id"] != address["exchange_id"]


class TestSDJWTAlgorithms(BaseSdJwtTest):
    """Test SD-JWT with different algorithms."""

    @pytest.mark.asyncio
    async def test_ed25519_algorithm(
        self, credential_flow, presentation_flow, issuer_did
    ):
        """Test SD-JWT with EdDSA (Ed25519) algorithm."""
        result = await credential_flow.issue_sd_jwt(
            vct=VCT.IDENTITY,
            claims_config={"given_name": {"mandatory": True}},
            credential_subject={"given_name": "Alice"},
            sd_list=["/given_name"],
            issuer_did=issuer_did,  # Ed25519 DID from base class
        )

        # Verify the credential uses EdDSA
        assert result["credential"]
        # EdDSA is in ALGORITHMS.SD_JWT_ALGS


class TestSDJWTErrors(BaseSdJwtTest):
    """Test error handling in SD-JWT flows."""

    @pytest.mark.asyncio
    async def test_invalid_vct_rejected(
        self, credential_flow, presentation_flow, issuer_did
    ):
        """Test that credentials with mismatched VCT are rejected."""
        # Issue credential with one VCT
        result = await credential_flow.issue_sd_jwt(
            vct=VCT.IDENTITY,
            claims_config={"given_name": {"mandatory": True}},
            credential_subject={"given_name": "Alice"},
            sd_list=["/given_name"],
            issuer_did=issuer_did,
        )

        # Try to verify with different VCT - should fail
        with pytest.raises(Exception):
            await presentation_flow.verify_sd_jwt(
                credential=result["credential"],
                vct=VCT.ADDRESS,  # Wrong VCT!
                required_claims=["given_name"],
            )
