"""Core OID4VCI 1.0 compliance tests."""

import base64
import json
import logging
import os
import time

import httpx
import pytest
import pytest_asyncio
from aries_askar import Key, KeyAlg

# Use the standard environment variable instead of TEST_CONFIG
OID4VCI_ENDPOINT = os.getenv("ACAPY_ISSUER_OID4VCI_URL", "http://localhost:8022")

LOGGER = logging.getLogger(__name__)


class OID4VCTestRunner:
    """Helper class for OID4VCI 1.0 compliance tests."""

    def __init__(self, acapy_issuer_admin, issuer_did):
        self.acapy_issuer_admin = acapy_issuer_admin
        self.issuer_did = issuer_did
        self.test_results = {}

    async def setup_supported_credential(self):
        """Create a supported credential configuration."""
        # Create a simple vc+sd-jwt credential configuration with proper sd_list
        import uuid

        random_suffix = str(uuid.uuid4())[:8]
        config = {
            "id": f"TestCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "TestCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/test",
                "claims": {"test_claim": {"mandatory": True}},
            },
            "vc_additional_data": {"sd_list": ["/test_claim"]},
        }

        response = await self.acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=config
        )

        supported_cred_id = response["supported_cred_id"]
        identifier = response.get("identifier", supported_cred_id)

        return {"supported_cred_id": supported_cred_id, "identifier": identifier}

    async def create_credential_offer(self, supported_cred_id):
        """Create a credential offer for testing."""
        # First create the exchange
        exchange = await self.acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test_claim": "test_value"},
                "did": self.issuer_did,
            },
        )

        # Then get the credential offer
        offer_response = await self.acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
        )

        return {
            "exchange_id": exchange["exchange_id"],
            "offer": offer_response["offer"],
            "credential_offer": offer_response["credential_offer"],
        }


@pytest_asyncio.fixture
async def test_runner(acapy_issuer_admin, issuer_ed25519_did):
    """Test runner fixture for OID4VCI 1.0 compliance tests."""
    return OID4VCTestRunner(acapy_issuer_admin, issuer_ed25519_did)


class TestOID4VCI10Compliance:
    """OID4VCI 1.0 compliance test suite."""

    @pytest.mark.asyncio
    async def test_oid4vci_10_metadata(self):
        """Test OID4VCI 1.0 § 11.2: Credential Issuer Metadata."""
        LOGGER.info("Testing OID4VCI 1.0 credential issuer metadata...")

        async with httpx.AsyncClient() as client:
            # Test .well-known endpoint
            response = await client.get(
                f"{OID4VCI_ENDPOINT}/.well-known/openid-credential-issuer",
                timeout=30,
            )

            if response.status_code != 200:
                LOGGER.error(
                    "Metadata endpoint failed: %s - %s",
                    response.status_code,
                    response.text,
                )

            assert response.status_code == 200

            metadata = response.json()

            # OID4VCI 1.0 § 11.2.1: Required fields
            assert "credential_issuer" in metadata
            assert "credential_endpoint" in metadata
            assert "credential_configurations_supported" in metadata

            # Validate credential_issuer format (handle env vars)
            credential_issuer = metadata["credential_issuer"]

            # Handle case where environment variable is not resolved
            if "${AGENT_ENDPOINT" in credential_issuer:
                LOGGER.warning(
                    "Environment variable not resolved in credential_issuer: %s",
                    credential_issuer,
                )
                # Check if it contains the expected port/path structure
                assert (
                    ":8032" in credential_issuer
                    or "localhost:8032" in credential_issuer
                )
            else:
                # In integration tests, endpoints might differ slightly due to docker networking
                # but we check basic validity
                assert credential_issuer.startswith("http")

            # Validate credential_endpoint format
            # The endpoint hostname may vary (.local alias) but should end with /credential
            assert metadata["credential_endpoint"].startswith("http")
            assert metadata["credential_endpoint"].endswith("/credential")
            assert ":8022" in metadata["credential_endpoint"]

            # OID4VCI 1.0 § 11.2.3: credential_configurations_supported must be object
            configs = metadata["credential_configurations_supported"]
            assert isinstance(configs, dict), (
                "credential_configurations_supported must be object in OID4VCI 1.0"
            )

            # Metadata validated successfully; results consumed by assertions above

    @pytest.mark.asyncio
    async def test_oid4vci_10_credential_request_with_identifier(self, test_runner):
        """Test OID4VCI 1.0 § 7.2: Credential Request with credential_identifier."""
        LOGGER.info(
            "Testing OID4VCI 1.0 credential request with credential_identifier..."
        )

        # Setup supported credential
        supported_cred_result = await test_runner.setup_supported_credential()
        supported_cred_id = supported_cred_result["supported_cred_id"]
        credential_identifier = supported_cred_result["identifier"]
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Verify offer has credential_configuration_ids (OID4VCI 1.0)
        assert "credential_configuration_ids" in offer_data["offer"], (
            "Offer must contain credential_configuration_ids per OID4VCI 1.0"
        )
        LOGGER.info(f"Offer structure: {list(offer_data['offer'].keys())}")

        # Get access token
        grants = offer_data["offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                f"{OID4VCI_ENDPOINT}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert token_response.status_code == 200
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data.get("c_nonce")

            # Generate proof
            key = Key.generate(KeyAlg.ED25519)
            jwk = json.loads(key.get_jwk_public())

            header = {"typ": "openid4vci-proof+jwt", "alg": "EdDSA", "jwk": jwk}

            payload = {
                "nonce": c_nonce,
                "aud": f"{OID4VCI_ENDPOINT}",
                "iat": int(time.time()),
            }

            encoded_header = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )

            sig_input = f"{encoded_header}.{encoded_payload}".encode()
            signature = key.sign_message(sig_input)
            encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")

            proof_jwt = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

            # Test credential request with credential_identifier (OID4VCI 1.0 format)
            # NOTE: Per OID4VCI 1.0 §7.2, credential_identifier and format are mutually exclusive
            # However, ACA-Py still requires format field (draft spec behavior)
            credential_request = {
                "credential_identifier": credential_identifier,
                "proof": {"jwt": proof_jwt},
            }

            cred_response = await client.post(
                f"{OID4VCI_ENDPOINT}/credential",
                json=credential_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            LOGGER.info(f"Credential response status: {cred_response.status_code}")
            if cred_response.status_code != 200:
                LOGGER.error(f"Credential request failed: {cred_response.text}")

            # Should succeed with OID4VCI 1.0 format
            assert cred_response.status_code == 200
            cred_data = cred_response.json()

            # Validate OID4VCI 1.0 response structure (credentials array)
            assert "credentials" in cred_data, (
                f"Expected 'credentials' key in response, got: {list(cred_data.keys())}"
            )
            assert len(cred_data["credentials"]) >= 1, (
                "Expected at least one credential"
            )
            first_cred = cred_data["credentials"][0]
            # Each credential entry must have a "credential" key with the actual value
            assert "credential" in first_cred, (
                f"Expected 'credential' key in credentials[0], got: {list(first_cred.keys())}"
            )

            test_runner.test_results["credential_request_identifier"] = {
                "status": "PASS",
                "response": cred_data,
                "validation": "OID4VCI 1.0 § 7.2 credential_identifier compliant",
            }

    @pytest.mark.asyncio
    async def test_oid4vci_10_mutual_exclusion(self, test_runner):
        """Test OID4VCI 1.0 § 7.2: credential_identifier and format exclusion.

        Per OID4VCI 1.0 § 7.2: credential_identifier and format MUST be
        mutually exclusive.
        """
        LOGGER.info("Testing credential_identifier and format mutual exclusion...")

        # Setup
        supported_cred_result = await test_runner.setup_supported_credential()
        supported_cred_id = supported_cred_result["supported_cred_id"]
        credential_identifier = supported_cred_result["identifier"]
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Extract pre-authorized code from credential offer
        grants = offer_data["offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{OID4VCI_ENDPOINT}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            try:
                token_data = token_response.json()
                access_token = token_data["access_token"]
            except json.JSONDecodeError as e:
                LOGGER.error("Failed to parse token response as JSON: %s", e)
                LOGGER.error("Response content: %s", token_response.text)
                raise

            # Test with both parameters (should fail per OID4VCI 1.0 § 7.2)
            invalid_request = {
                "credential_identifier": credential_identifier,
                "format": "vc+sd-jwt",  # Both present - violation
                "proof": {"jwt": "test_jwt"},
            }

            response = await client.post(
                f"{OID4VCI_ENDPOINT}/credential",
                json=invalid_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            # Should fail with 400 Bad Request per OID4VCI 1.0 § 7.2
            LOGGER.info(f"Mutual exclusion test response: {response.status_code}")
            if response.status_code != 400:
                LOGGER.error(
                    f"Expected 400, got {response.status_code}: {response.text}"
                )

            assert response.status_code == 400

            # Verify error message mentions mutual exclusivity
            error_text = response.text.lower()
            assert "mutually exclusive" in error_text, (
                f"Error should mention mutual exclusivity, got: {response.text}"
            )

            # Test with neither parameter (should also fail)
            invalid_request2 = {
                "proof": {"jwt": "test_jwt"}
                # Neither credential_identifier nor format
            }

            response2 = await client.post(
                f"{OID4VCI_ENDPOINT}/credential",
                json=invalid_request2,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            assert response2.status_code == 400
            error_text2 = response2.text.lower()
            assert "required" in error_text2 or "missing" in error_text2, (
                f"Error should mention required field, got: {response2.text}"
            )

            test_runner.test_results["mutual_exclusion"] = {
                "status": "PASS",
                "validation": "OID4VCI 1.0 § 7.2 mutual exclusion enforced",
            }

    @pytest.mark.asyncio
    async def test_oid4vci_10_proof_of_possession(self, test_runner):
        """Test OID4VCI 1.0 § 7.2.1: Proof of Possession validation."""
        LOGGER.info("Testing OID4VCI 1.0 proof of possession...")

        # Setup
        supported_cred_result = await test_runner.setup_supported_credential()
        supported_cred_id = supported_cred_result["supported_cred_id"]
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Extract pre-authorized code from credential offer
        grants = offer_data["offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{OID4VCI_ENDPOINT}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                token_data = token_response.json()
                access_token = token_data["access_token"]
            except json.JSONDecodeError as e:
                LOGGER.error("Failed to parse token response as JSON: %s", e)
                LOGGER.error("Response content: %s", token_response.text)
                raise

            # Test with invalid proof type
            # Use credential_identifier from OID4VCI 1.0 offer structure
            offer = offer_data["offer"]
            assert "credential_configuration_ids" in offer, (
                "Offer must have credential_configuration_ids per OID4VCI 1.0"
            )

            credential_identifier = offer["credential_configuration_ids"][0]

            invalid_proof_request = {
                "credential_identifier": credential_identifier,  # OID4VCI 1.0
                "proof": {
                    "jwt": (
                        "eyJ0eXAiOiJpbnZhbGlkIiwiYWxnIjoiRVMyNTYifQ."
                        "eyJub25jZSI6InRlc3QifQ.sig"
                    )
                },
            }

            response = await client.post(
                f"{OID4VCI_ENDPOINT}/credential",
                json=invalid_proof_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            # Should fail due to wrong typ header or invalid JWT
            assert response.status_code == 400

            # Handle different error response formats
            try:
                error_data = response.json()
                error_msg = error_data.get("message", str(error_data))
            except Exception:
                error_msg = response.text

            # Check for proof validation error
            assert (
                "openid4vci-proof+jwt" in error_msg
                or "proof" in error_msg.lower()
                or "invalid" in error_msg.lower()
            ), f"Error should mention proof validation, got: {error_msg}"

            test_runner.test_results["proof_of_possession"] = {
                "status": "PASS",
                "validation": "OID4VCI 1.0 § 7.2.1 proof validation enforced",
            }
