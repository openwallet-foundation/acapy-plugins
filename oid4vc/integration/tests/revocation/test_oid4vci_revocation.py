"""OID4VCI Revocation tests."""

import base64
import json
import logging
import time
import zlib

import httpx
import jwt
import pytest
from acapy_agent.wallet.util import bytes_to_b64
from bitarray import bitarray
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.helpers import TEST_CONFIG

# OID4VCTestHelper was legacy - tests should use inline logic or base classes

LOGGER = logging.getLogger(__name__)


class TestOID4VCIRevocation:
    """OID4VCI Revocation test suite."""

    @pytest.mark.skip(reason="Legacy test needing refactor")
    @pytest.mark.asyncio
    async def test_revocation_status_in_credential(self, test_runner):
        """Test that issued credential contains revocation status."""
        LOGGER.info("Testing revocation status in credential...")

        # Setup supported credential
        supported_cred_result = await test_runner.setup_supported_credential()
        supported_cred_id = supported_cred_result["supported_cred_id"]
        LOGGER.info(f"Supported Credential ID: {supported_cred_id}")

        # Create a DID to use as issuer for the status list
        async with httpx.AsyncClient() as client:
            did_create_response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/wallet/did/create",
                json={"method": "key", "options": {"key_type": "ed25519"}},
            )
            assert did_create_response.status_code == 200
            did_info = did_create_response.json()
            issuer_did = did_info["result"]["did"]
            LOGGER.info(f"Created issuer DID for status list: {issuer_did}")

            # Create Status List Definition
            status_def_response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/status-list/defs",
                json={
                    "supported_cred_id": supported_cred_id,
                    "status_purpose": "revocation",
                    "list_size": 1024,
                    "list_type": "ietf",
                    "issuer_did": issuer_did,
                },
            )
            if status_def_response.status_code != 200:
                LOGGER.error(
                    f"Failed to create status list def: {status_def_response.text}"
                )
            assert status_def_response.status_code == 200
            status_def = status_def_response.json()
            LOGGER.info(f"Status List Definition created: {status_def}")

        # Create offer and get credential
        offer_data = await test_runner.create_credential_offer(supported_cred_id)
        LOGGER.info(f"Offer Data: {offer_data}")

        credential_offer = offer_data["credential_offer"]
        if isinstance(credential_offer, str):
            if credential_offer.startswith("openid-credential-offer://"):
                from urllib.parse import parse_qs, urlparse

                parsed = urlparse(credential_offer)
                qs = parse_qs(parsed.query)
                if "credential_offer" in qs:
                    credential_offer = json.loads(qs["credential_offer"][0])
            else:
                credential_offer = json.loads(credential_offer)

        grants = credential_offer["grants"]
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
            assert token_response.status_code == 200
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data.get("c_nonce")

            # Generate Proof
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            numbers = public_key.public_numbers()
            x = bytes_to_b64(numbers.x.to_bytes(32, "big"), urlsafe=True, pad=False)
            y = bytes_to_b64(numbers.y.to_bytes(32, "big"), urlsafe=True, pad=False)

            jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
                "use": "sig",
                "alg": "ES256",
            }

            proof_payload = {
                "aud": TEST_CONFIG["oid4vci_endpoint"],
                "iat": int(time.time()),
                "nonce": c_nonce,
            }

            pem_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            proof_jwt = jwt.encode(
                proof_payload,
                pem_key,
                algorithm="ES256",
                headers={"jwk": jwk, "typ": "openid4vci-proof+jwt"},
            )

            # Get Credential
            credential_request = {
                "format": "jwt_vc_json",
                "proof": {"jwt": proof_jwt, "proof_type": "jwt"},
            }

            cred_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=credential_request,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if cred_response.status_code != 200:
                LOGGER.error(f"Credential request failed: {cred_response.text}")
            assert cred_response.status_code == 200
            credential_response = cred_response.json()

        assert "credential" in credential_response
        credential = credential_response["credential"]

        # Decode JWT to check payload
        # We assume it's a JWT string
        # import jwt
        # We don't verify signature here as we don't have the issuer's public key easily accessible in this context
        # and we trust the issuer (ACA-Py)
        payload = jwt.decode(credential, options={"verify_signature": False})
        LOGGER.info(f"Full JWT Payload: {json.dumps(payload, indent=2)}")

        vc = payload.get("vc", payload)
        LOGGER.info(f"VC Object: {json.dumps(vc, indent=2)}")

        assert "credentialStatus" in vc, "credentialStatus missing in credential"
        status = vc["credentialStatus"]
        print(f"DEBUG: Credential Status: {status}")

        # Verify Status Entry structure
        # It seems to be using the IETF status_list claim structure
        assert "status_list" in status
        status_list_entry = status["status_list"]
        assert "idx" in status_list_entry
        assert "uri" in status_list_entry

        status_list_url = status_list_entry["uri"]
        status_list_index = int(status_list_entry["idx"])

        LOGGER.info(f"Status List URL: {status_list_url}")
        LOGGER.info(f"Status List Index: {status_list_index}")

        # Resolve Status List
        async with httpx.AsyncClient() as client:
            response = await client.get(status_list_url)
            if response.status_code != 200:
                LOGGER.error(f"Failed to fetch status list: {response.text}")
            assert response.status_code == 200

            # The response is a JWT string (Status List Token)
            status_list_jwt = response.text
            LOGGER.info(f"Status List JWT: {status_list_jwt}")

            # Decode JWT
            payload_sl = jwt.decode(
                status_list_jwt, options={"verify_signature": False}
            )
            LOGGER.info(f"Status List Payload: {payload_sl}")

            # Verify payload structure for IETF Bitstring Status List
            assert "status_list" in payload_sl
            assert "bits" in payload_sl["status_list"]
            assert "lst" in payload_sl["status_list"]
            assert payload_sl["status_list"]["bits"] == 1

            # Verify the bit is set (or not set, depending on default)
            # By default, it should be 0 (not revoked)
            # We haven't revoked it yet.

            encoded_list_initial = payload_sl["status_list"]["lst"]
            missing_padding = len(encoded_list_initial) % 4
            if missing_padding:
                encoded_list_initial += "=" * (4 - missing_padding)

            compressed_bytes_initial = base64.urlsafe_b64decode(encoded_list_initial)
            bit_bytes_initial = zlib.decompress(compressed_bytes_initial)

            ba_initial = bitarray()
            ba_initial.frombytes(bit_bytes_initial)

            assert ba_initial[status_list_index] == 0, (
                "Credential should not be revoked initially"
            )
            LOGGER.info("Credential initially valid (bit set to 0)")

            # Test revocation (update status)

            # Let's revoke the credential and check again
            # We need the credential ID (jti) or the index to revoke.
            # The index is status_list_index.

            # Update status list entry
            # We need the definition ID.
            definition_id = status_def["id"]

            # We need the credential ID used in the status list binding.
            # In OID4VC plugin, the exchange_id is used as the credential_id for status list binding.
            cred_id = offer_data["exchange_id"]

            LOGGER.info(f"Revoking credential with ID (exchange_id): {cred_id}")

            # Let's try to revoke using the credential ID.
            # We need to find the endpoint to update status.
            # PATCH /status-list/defs/{def_id}/creds/{cred_id}

            update_response = await client.patch(
                f"{TEST_CONFIG['admin_endpoint']}/status-list/defs/{definition_id}/creds/{cred_id}",
                json={"status": "1"},  # Revoked
            )
            if update_response.status_code != 200:
                LOGGER.error(f"Failed to revoke credential: {update_response.text}")
            assert update_response.status_code == 200

            # Publish the update (if needed? The plugin might auto-publish or we need to trigger it)
            # The plugin has a publish endpoint: PUT /status-list/defs/{def_id}/publish
            publish_response = await client.put(
                f"{TEST_CONFIG['admin_endpoint']}/status-list/defs/{definition_id}/publish"
            )
            assert publish_response.status_code == 200

            # Fetch status list again and verify bit is 1
            response = await client.get(status_list_url)
            assert response.status_code == 200
            status_list_jwt = response.text
            payload = jwt.decode(status_list_jwt, options={"verify_signature": False})
            encoded_list = payload["status_list"]["lst"]

            # We need to decode the bitstring to verify the bit.
            # It's base64url encoded, then maybe gzipped/zlibbed?
            # In status_handler.py:
            # if definition.list_type == "ietf":
            #    bit_bytes = zlib.compress(bit_bytes)
            # base64 = bytes_to_b64(bit_bytes, True)

            # So: base64url decode -> zlib decompress -> bitarray

            # Add padding if needed for base64 decoding
            missing_padding = len(encoded_list) % 4
            if missing_padding:
                encoded_list += "=" * (4 - missing_padding)

            compressed_bytes = base64.urlsafe_b64decode(encoded_list)
            bit_bytes = zlib.decompress(compressed_bytes)

            ba = bitarray()
            ba.frombytes(bit_bytes)

            LOGGER.info(f"Bitarray length: {len(ba)}")
            LOGGER.info(f"Bitarray ones: {ba.count(1)}")
            if ba.count(1) > 0:
                try:
                    LOGGER.info(f"Index of first 1: {ba.index(1)}")
                except ValueError:
                    pass

            # Check the bit at status_list_index
            # Note: bitarray indexing might be different from what we expect?
            # But usually it's straightforward.

            assert ba[status_list_index] == 1
            LOGGER.info("Credential successfully revoked (bit set to 1)")

            LOGGER.info(f"Status List VC: {json.dumps(payload, indent=2)}")
            LOGGER.info("Revocation status verified successfully")
