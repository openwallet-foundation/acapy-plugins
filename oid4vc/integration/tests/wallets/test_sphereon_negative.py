import uuid

import pytest


@pytest.mark.asyncio
async def test_sphereon_accept_offer_invalid_proof(acapy_issuer_admin, sphereon_client):
    """Test Sphereon accepting a credential offer with an invalid proof of possession."""

    # 1. Setup Issuer (ACA-Py)
    cred_id = f"UniversityDegreeCredential-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    # Create exchange
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # 2. Sphereon accepts offer with INVALID PROOF
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer, "invalid_proof": True},
    )

    # Expecting failure
    # The wrapper returns 500 if the client throws an error
    assert response.status_code == 500
    error_data = response.json()
    # The error message from ACA-Py should be about signature verification
    # Note: The exact error message depends on how the client library reports the server error
    # But we expect it to fail.
    print(f"Received expected error: {error_data}")
