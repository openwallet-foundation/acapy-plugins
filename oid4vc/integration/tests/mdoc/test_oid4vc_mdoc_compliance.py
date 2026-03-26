"""OID4VC integration tests with mso_mdoc format (ISO 18013-5)."""

import base64
import logging
import time
import uuid

import cbor2
import httpx
import pytest
from cbor2 import CBORTag

from tests.helpers import MDOC_AVAILABLE, TEST_CONFIG, mdl

# OID4VCTestHelper was legacy - tests should use inline logic or base classes

LOGGER = logging.getLogger(__name__)


@pytest.mark.skip(reason="Legacy test needing refactor")
@pytest.mark.mdoc
class TestOID4VCMdocCompliance:
    """Test OID4VC integration with mso_mdoc format (ISO 18013-5)."""

    @pytest.fixture(scope="class")
    def test_runner(self):
        """Setup test runner."""
        runner = {}
        yield runner

    @pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
    @pytest.mark.asyncio
    async def test_mdoc_credential_issuer_metadata(self, test_runner):
        """Test that credential issuer metadata includes mso_mdoc support."""
        LOGGER.info("Testing mso_mdoc metadata support...")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{TEST_CONFIG['oid4vci_endpoint']}/.well-known/openid-credential-issuer"
            )
            assert response.status_code == 200

            metadata = response.json()
            configs = metadata["credential_configurations_supported"]

            # Look for mso_mdoc format support
            mdoc_config = None
            for config_id, config in configs.items():
                if config.get("format") == "mso_mdoc":
                    mdoc_config = config
                    break

            # If no existing mdoc config, create one for testing
            if mdoc_config is None:
                LOGGER.info("No mso_mdoc config found, creating test configuration...")
                await test_runner.setup_mdoc_credential()

                # Re-fetch metadata to verify the configuration was added
                response = await client.get(
                    f"{TEST_CONFIG['oid4vci_endpoint']}/.well-known/openid-credential-issuer"
                )
                metadata = response.json()
                configs = metadata["credential_configurations_supported"]

                # Find the created mdoc config
                for config in configs.values():
                    if config.get("format") == "mso_mdoc":
                        mdoc_config = config
                        break

            assert mdoc_config is not None, "mso_mdoc configuration should be available"
            assert mdoc_config["format"] == "mso_mdoc"
            assert "doctype" in mdoc_config
            assert "cryptographic_binding_methods_supported" in mdoc_config
            assert "cose_key" in mdoc_config["cryptographic_binding_methods_supported"]

            test_runner.test_results["mdoc_metadata"] = {
                "status": "PASS",
                "mdoc_config": mdoc_config,
                "validation": "mso_mdoc format supported in credential issuer metadata",
            }

    @pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
    @pytest.mark.asyncio
    async def test_mdoc_credential_request_flow(self, test_runner):
        """Test complete mso_mdoc credential request flow."""
        LOGGER.info("Testing complete mso_mdoc credential request flow...")

        # Setup mdoc credential
        supported_cred = await test_runner.setup_mdoc_credential()
        offer_data = await test_runner.create_mdoc_credential_offer(supported_cred)

        # Extract holder key for proof generation
        holder_key = offer_data["holder_key"]
        holder_did = offer_data["did"]

        # Get access token using pre-authorized code flow
        grants = offer_data["offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            if token_response.status_code != 200:
                LOGGER.error(
                    "Token request failed: %s - %s",
                    token_response.status_code,
                    token_response.text,
                )
            assert token_response.status_code == 200
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data.get("c_nonce")

            # Create CWT proof
            # COSE_Sign1: [protected, unprotected, payload, signature]
            # Protected header: {1: -7} (Alg: ES256) -> b'\xa1\x01\x26'
            protected_header = {1: -7}
            protected_header_bytes = cbor2.dumps(protected_header)

            claims = {
                "aud": TEST_CONFIG["oid4vci_endpoint"],
                "iat": int(time.time()),
            }
            if c_nonce:
                claims["nonce"] = c_nonce

            payload_bytes = cbor2.dumps(claims)

            # Sig_structure: ['Signature1', protected, external_aad, payload]
            sig_structure = ["Signature1", protected_header_bytes, b"", payload_bytes]
            sig_structure_bytes = cbor2.dumps(sig_structure)

            signature = holder_key.sign(sig_structure_bytes)

            # Construct COSE_Sign1
            unprotected_header = {4: holder_did.encode()}
            cose_sign1 = [
                protected_header_bytes,
                unprotected_header,
                payload_bytes,
                signature,
            ]
            cwt_bytes = cbor2.dumps(CBORTag(18, cose_sign1))
            cwt_proof = base64.urlsafe_b64encode(cwt_bytes).decode().rstrip("=")

            # Create mdoc credential request
            # For mso_mdoc, we use credential_identifier (OID4VCI 1.0 style)
            credential_request = {
                "credential_identifier": supported_cred["id"],
                "doctype": "org.iso.18013.5.1.mDL",
                "proof": {
                    "proof_type": "cwt",
                    "cwt": cwt_proof,
                },
            }

            # Request credential
            cred_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=credential_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if cred_response.status_code != 200:
                LOGGER.error(f"Credential request failed: {cred_response.text}")
            assert cred_response.status_code == 200
            cred_data = cred_response.json()

            # Validate mso_mdoc response structure
            assert "format" in cred_data
            assert cred_data["format"] == "mso_mdoc"
            assert "credential" in cred_data

            # The credential should be a CBOR-encoded mso_mdoc
            mdoc_credential = cred_data["credential"]
            assert isinstance(mdoc_credential, str), (
                "mso_mdoc should be base64-encoded string"
            )

            test_runner.test_results["mdoc_credential_flow"] = {
                "status": "PASS",
                "response": cred_data,
                "validation": "Complete mso_mdoc credential request flow successful",
            }

    @pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
    @pytest.mark.asyncio
    async def test_mdoc_presentation_workflow(self, test_runner):
        """Test mdoc presentation workflow using isomdl_uniffi."""
        LOGGER.info("Testing mdoc presentation workflow with isomdl_uniffi...")

        # Generate test mdoc using isomdl_uniffi
        holder_key = mdl.P256KeyPair()
        test_mdl = mdl.generate_test_mdl(holder_key)

        # Verify mdoc properties
        assert test_mdl.doctype() == "org.iso.18013.5.1.mDL"
        mdoc_id = test_mdl.id()
        assert mdoc_id is not None

        # Test serialization capabilities
        mdoc_json = test_mdl.json()
        assert len(mdoc_json) > 0

        mdoc_cbor = test_mdl.stringify()
        assert len(mdoc_cbor) > 0

        # Test presentation session creation
        ble_uuid = str(uuid.uuid4())
        session = mdl.MdlPresentationSession(test_mdl, ble_uuid)

        # Generate QR code for presentation
        qr_code = session.get_qr_code_uri()
        assert qr_code.startswith("mdoc:"), "QR code should start with mdoc: scheme"

        # Test verification workflow
        requested_attributes = {
            "org.iso.18013.5.1": {
                "given_name": True,
                "family_name": True,
                "birth_date": True,
            }
        }

        # Establish reader session
        reader_data = mdl.establish_session(qr_code, requested_attributes, None)
        assert reader_data is not None

        # Handle request from verifier
        session.handle_request(reader_data.request)

        # Build response with permitted attributes
        permitted_items = {}
        # Simplified for test - in real scenario would process requested_data
        permitted_items["org.iso.18013.5.1.mDL"] = {
            "org.iso.18013.5.1": ["given_name", "family_name", "birth_date"]
        }

        # Generate and sign presentation response
        unsigned_response = session.generate_response(permitted_items)
        signed_response = holder_key.sign(unsigned_response)
        presentation_response = session.submit_response(signed_response)

        # Verify the presentation
        verification_result = mdl.handle_response(
            reader_data.state, presentation_response
        )

        # Validate verification results
        assert (
            verification_result.device_authentication == mdl.AuthenticationStatus.VALID
        )
        assert verification_result.verified_response is not None
        assert len(verification_result.verified_response) > 0

        test_runner.test_results["mdoc_presentation_workflow"] = {
            "status": "PASS",
            "mdoc_doctype": test_mdl.doctype(),
            "qr_code_length": len(qr_code),
            "verification_status": str(verification_result.device_authentication),
            "disclosed_attributes": list(verification_result.verified_response.keys()),
            "validation": "Complete mdoc presentation workflow successful",
        }

    @pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
    @pytest.mark.asyncio
    async def test_mdoc_interoperability_reader_sessions(self, test_runner):
        """Test interoperability between OID4VC issuance and mdoc presentation."""
        LOGGER.info("Testing OID4VC-to-mdoc interoperability...")

        # Phase 1: Issue credential via OID4VC
        supported_cred = await test_runner.setup_mdoc_credential()
        offer_data = await test_runner.create_mdoc_credential_offer(supported_cred)
        holder_key = offer_data["holder_key"]
        holder_did = offer_data["did"]

        # Get credential via OID4VC flow
        grants = offer_data["offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data.get("c_nonce")

            # Create CWT proof
            protected_header = {1: -7}
            protected_header_bytes = cbor2.dumps(protected_header)

            claims = {
                "aud": TEST_CONFIG["oid4vci_endpoint"],
                "iat": int(time.time()),
            }
            if c_nonce:
                claims["nonce"] = c_nonce

            payload_bytes = cbor2.dumps(claims)

            sig_structure = ["Signature1", protected_header_bytes, b"", payload_bytes]
            sig_structure_bytes = cbor2.dumps(sig_structure)

            signature = holder_key.sign(sig_structure_bytes)

            unprotected_header = {4: holder_did.encode()}
            cose_sign1 = [
                protected_header_bytes,
                unprotected_header,
                payload_bytes,
                signature,
            ]
            cwt_bytes = cbor2.dumps(CBORTag(18, cose_sign1))
            cwt_proof = base64.urlsafe_b64encode(cwt_bytes).decode().rstrip("=")

            # Request mso_mdoc credential
            credential_request = {
                "credential_identifier": supported_cred["id"],
                "doctype": "org.iso.18013.5.1.mDL",
                "proof": {
                    "proof_type": "cwt",
                    "cwt": cwt_proof,
                },
            }

            cred_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=credential_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if cred_response.status_code != 200:
                LOGGER.error(f"Credential request failed: {cred_response.text}")
            assert cred_response.status_code == 200
            cred_data = cred_response.json()

            # Phase 2: Use issued credential in mdoc presentation
            # Parse the issued credential using isomdl_uniffi
            issued_mdoc_b64 = cred_data["credential"]

            key_alias = "parsed"
            issued_mdoc = mdl.Mdoc.new_from_base64url_encoded_issuer_signed(
                issued_mdoc_b64, key_alias
            )

            # Create presentation session with the ISSUED credential
            session = mdl.MdlPresentationSession(issued_mdoc, str(uuid.uuid4()))
            qr_code = session.get_qr_code_uri()

            # Test verification workflow
            requested_attributes = {
                "org.iso.18013.5.1": {"given_name": True, "family_name": True}
            }

            reader_data = mdl.establish_session(qr_code, requested_attributes, None)
            session.handle_request(reader_data.request)

            # Generate presentation
            permitted_items = {
                "org.iso.18013.5.1.mDL": {
                    "org.iso.18013.5.1": ["given_name", "family_name"]
                }
            }

            unsigned_response = session.generate_response(permitted_items)
            signed_response = holder_key.sign(unsigned_response)
            presentation_response = session.submit_response(signed_response)

            # Verify presentation
            verification_result = mdl.handle_response(
                reader_data.state, presentation_response
            )
            assert (
                verification_result.device_authentication
                == mdl.AuthenticationStatus.VALID
            )

            test_runner.test_results["oid4vc_mdoc_interoperability"] = {
                "status": "PASS",
                "oid4vc_credential_format": cred_data["format"],
                "mdoc_verification_status": str(
                    verification_result.device_authentication
                ),
                "validation": (
                    "OID4VC mso_mdoc issuance and mdoc presentation "
                    "interoperability successful using issued credential"
                ),
            }
