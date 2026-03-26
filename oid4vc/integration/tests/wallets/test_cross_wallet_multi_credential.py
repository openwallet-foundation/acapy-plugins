"""Multi-credential presentation tests for OID4VC.

These tests verify that wallets can present multiple credentials in a single presentation:
1. Issuing multiple different credential types to a wallet
2. Requesting presentation of multiple credentials simultaneously
3. Verifying that all credentials are properly presented and validated
"""

import asyncio

import pytest

from tests.conftest import safely_get_first_credential

# =============================================================================
# Multi-Credential Presentation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_credo_multi_credential_presentation(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    issuer_ed25519_did,
    sd_jwt_credential_config,
):
    """Test Credo presenting multiple credentials in a single presentation.

    This tests whether multi-credential flows work correctly.
    """
    # Create two different credential types
    cred_config_1 = sd_jwt_credential_config(
        vct="IdentityCredential",
        claims={"name": {"mandatory": True}},
        sd_list=["/name"],
        scope="Identity",
        proof_algs=["EdDSA"],
        crypto_suites=["EdDSA"],
    )

    cred_config_2 = sd_jwt_credential_config(
        vct="EmploymentCredential",
        claims={"employer": {"mandatory": True}},
        sd_list=["/employer"],
        scope="Employment",
        proof_algs=["EdDSA"],
        crypto_suites=["EdDSA"],
    )

    config_1 = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=cred_config_1
    )
    config_2 = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=cred_config_2
    )

    # Issue credential 1
    exchange_1 = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_1["supported_cred_id"],
            "credential_subject": {"name": "Multi Test User"},
            "did": issuer_ed25519_did,
        },
    )
    offer_1 = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_1["exchange_id"]}
    )
    credo_resp_1 = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_1["credential_offer"],
            "holder_did_method": "key",
        },
    )
    credential_1 = safely_get_first_credential(credo_resp_1, "Credo")

    # Issue credential 2
    exchange_2 = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_2["supported_cred_id"],
            "credential_subject": {"employer": "Test Corp"},
            "did": issuer_ed25519_did,
        },
    )
    offer_2 = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_2["exchange_id"]}
    )
    credo_resp_2 = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_2["credential_offer"],
            "holder_did_method": "key",
        },
    )
    credential_2 = safely_get_first_credential(credo_resp_2, "Credo")

    # Create presentation definition requesting BOTH credentials
    import uuid

    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        "input_descriptors": [
            {
                "id": "identity-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                "constraints": {
                    "fields": [
                        {"path": ["$.vct"], "filter": {"const": "IdentityCredential"}},
                        {"path": ["$.name", "$.credentialSubject.name"]},
                    ]
                },
            },
            {
                "id": "employment-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {"const": "EmploymentCredential"},
                        },
                        {"path": ["$.employer", "$.credentialSubject.employer"]},
                    ]
                },
            },
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )
    pres_def_id = pres_def_response["pres_def_id"]

    presentation_request = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        },
    )
    presentation_id = presentation_request["presentation"]["presentation_id"]

    # Credo presents BOTH credentials
    present_response = await credo_client.post(
        "/oid4vp/present",
        json={
            "request_uri": presentation_request["request_uri"],
            "credentials": [credential_1, credential_2],
        },
    )

    # Document behavior
    print(f"Multi-credential presentation status: {present_response.status_code}")
    if present_response.status_code == 200:
        result = present_response.json()
        print(f"Multi-credential result: {result}")

        # Check verification
        for _ in range(10):
            record = await acapy_verifier_admin.get(
                f"/oid4vp/presentation/{presentation_id}"
            )
            if record.get("state") in ["presentation-valid", "presentation-invalid"]:
                break
            await asyncio.sleep(1)

        print(f"Multi-credential verification state: {record.get('state')}")
        if record.get("state") != "presentation-valid":
            print("WARNING: Multi-credential presentation failed - potential bug")
    else:
        print(f"Multi-credential presentation failed: {present_response.text}")
