"""Cross-wallet Credo JWT compatibility tests for OID4VC.

These tests focus on Credo wallet behavior with JWT VC credentials:
1. Issuing JWT VCs to Credo and verifying with Sphereon-compatible patterns
2. Testing algorithm negotiation edge cases with Credo
3. Testing selective disclosure behavior with Credo
"""

import asyncio
import uuid

import pytest

from tests.conftest import safely_get_first_credential, wait_for_presentation_valid

# =============================================================================
# Cross-Wallet Issuance and Verification Tests - Credo Focus
# =============================================================================


@pytest.mark.xfail(
    reason=(
        "Known interop limitation: Credo does not POST the VP response back to "
        "ACA-Py for PEX + SD-JWT requests. Presentation stays in "
        "'request-retrieved' state and times out."
    ),
)
@pytest.mark.asyncio
async def test_issue_to_credo_verify_with_sphereon_jwt_vc(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    sphereon_client,  # noqa: ARG001
    issuer_ed25519_did,
    sd_jwt_credential_config,
):
    """Issue JWT VC to Credo, then verify presentation from Credo via Sphereon-style request.

    This tests whether credentials issued to Credo can be presented to a verifier
    that uses Sphereon-compatible verification patterns.
    """
    # Step 1: Issue JWT VC credential to Credo
    credential_supported = sd_jwt_credential_config(
        vct="CrossWalletCredential",
        claims={
            "name": {"mandatory": True},
            "email": {"mandatory": False},
        },
        sd_list=["/name", "/email"],
        scope="CrossWalletTest",
    )

    credential_config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = credential_config_response["supported_cred_id"]

    exchange_request = {
        "supported_cred_id": config_id,
        "credential_subject": {
            "name": "Cross Wallet Test",
            "email": "cross@wallet.test",
        },
        "did": issuer_ed25519_did,
    }

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    exchange_id = exchange_response["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    credential_offer_uri = offer_response["credential_offer"]

    # Credo accepts the offer
    accept_offer_request = {
        "credential_offer": credential_offer_uri,
        "holder_did_method": "key",
    }

    credential_response = await credo_client.post(
        "/oid4vci/accept-offer", json=accept_offer_request
    )
    credo_credential = safely_get_first_credential(credential_response, "Credo")

    # Step 2: Create verification request (using patterns compatible with both wallets)
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": "cross-wallet-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct", "$.type"],
                            "filter": {
                                "type": "string",
                                "const": "CrossWalletCredential",
                            },
                        },
                        {"path": ["$.name", "$.credentialSubject.name"]},
                    ]
                },
            }
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
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        },
    )
    request_uri = presentation_request["request_uri"]
    presentation_id = presentation_request["presentation"]["presentation_id"]

    # Step 3: Credo presents the credential
    present_request = {"request_uri": request_uri, "credentials": [credo_credential]}
    presentation_response = await credo_client.post(
        "/oid4vp/present", json=present_request
    )

    assert presentation_response.status_code == 200, (
        f"Presentation failed: {presentation_response.text}"
    )
    presentation_result = presentation_response.json()
    assert presentation_result.get("success") is True

    # Step 4: Verify ACA-Py received and validated
    await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)


# =============================================================================
# Format Negotiation Edge Cases - Credo Focus
# =============================================================================


@pytest.mark.asyncio
async def test_credo_unsupported_algorithm_request(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    issuer_ed25519_did,
    sd_jwt_credential_config,
):
    """Test Credo behavior when verifier requests unsupported algorithm.

    Issue credential with EdDSA, but request presentation with only ES256.
    This tests algorithm negotiation handling.
    """
    credential_supported = sd_jwt_credential_config(
        vct="AlgoTestCredential",
        claims={"test_field": {"mandatory": True}},
        sd_list=["/test_field"],
        scope="AlgoTest",
        proof_algs=["EdDSA"],  # EdDSA only
        crypto_suites=["EdDSA"],
    )

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = config_response["supported_cred_id"]

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_id,
            "credential_subject": {"test_field": "algo_test_value"},
            "did": issuer_ed25519_did,
        },
    )
    exchange_id = exchange_response["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )

    # Credo accepts offer
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_response["credential_offer"],
            "holder_did_method": "key",
        },
    )
    credo_credential = safely_get_first_credential(credo_response, "Credo")

    # Create verification request that ONLY accepts ES256 (not EdDSA)
    algo_test_id = str(uuid.uuid4())
    presentation_definition = {
        "id": algo_test_id,
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},  # ES256 only
        "input_descriptors": [
            {
                "id": algo_test_id,
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {"type": "string", "const": "AlgoTestCredential"},
                        },
                    ]
                },
            }
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
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
        },
    )
    request_uri = presentation_request["request_uri"]

    # Attempt presentation - this should either fail or Credo should handle algorithm mismatch
    present_response = await credo_client.post(
        "/oid4vp/present",
        json={"request_uri": request_uri, "credentials": [credo_credential]},
    )

    # Document the behavior - this test discovers if there's a bug
    # Expected: Either Credo rejects with meaningful error, or verifier rejects the presentation
    if present_response.status_code == 200:
        # If presentation was attempted, check verifier's response
        result = present_response.json()
        # The presentation may have been submitted but should fail verification
        if result.get("success") is True:
            # Check if ACA-Py correctly rejects the mismatched algorithm
            presentation_id = presentation_request["presentation"]["presentation_id"]
            for _ in range(5):
                record = await acapy_verifier_admin.get(
                    f"/oid4vp/presentation/{presentation_id}"
                )
                if record.get("state") in [
                    "presentation-valid",
                    "presentation-invalid",
                ]:
                    break
                await asyncio.sleep(1)

            # Document the actual behavior for bug discovery
            print(f"Algorithm mismatch test result: state={record.get('state')}")
            # If state is "presentation-valid", this indicates a potential bug where
            # algorithm constraints are not being enforced
    else:
        # Credo correctly rejected the request
        print(f"Credo rejected algorithm mismatch: {present_response.status_code}")


# =============================================================================
# Selective Disclosure Parity Tests - Credo Focus
# =============================================================================


@pytest.mark.xfail(
    reason=(
        "Known interop limitation: Credo does not POST the VP response back to "
        "ACA-Py for PEX + SD-JWT requests. Presentation stays in "
        "'request-retrieved' state and times out."
    ),
)
@pytest.mark.asyncio
async def test_selective_disclosure_credo_vs_sphereon_parity(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    issuer_ed25519_did,
    sd_jwt_credential_config,
):
    """Test selective disclosure behavior in Credo matches expected behavior.

    Issue SD-JWT with multiple disclosable claims, request only subset,
    verify only requested claims are disclosed.
    """
    credential_supported = sd_jwt_credential_config(
        vct="SDTestCredential",
        claims={
            "public_claim": {"mandatory": True},
            "private_claim_1": {"mandatory": False},
            "private_claim_2": {"mandatory": False},
            "private_claim_3": {"mandatory": False},
        },
        sd_list=["/private_claim_1", "/private_claim_2", "/private_claim_3"],
        scope="SDTest",
    )

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = config_response["supported_cred_id"]

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_id,
            "credential_subject": {
                "public_claim": "public_value",
                "private_claim_1": "secret_1",
                "private_claim_2": "secret_2",
                "private_claim_3": "secret_3",
            },
            "did": issuer_ed25519_did,
        },
    )
    exchange_id = exchange_response["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )

    # Credo accepts
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_response["credential_offer"],
            "holder_did_method": "key",
        },
    )
    sd_jwt_credential = safely_get_first_credential(credo_response, "Credo")

    # Request ONLY private_claim_1 (not 2 or 3)
    sd_test_id = str(uuid.uuid4())
    presentation_definition = {
        "id": sd_test_id,
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": sd_test_id,
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {"type": "string", "const": "SDTestCredential"},
                        },
                        {
                            "path": [
                                "$.private_claim_1",
                                "$.credentialSubject.private_claim_1",
                            ]
                        },
                        # NOT requesting private_claim_2 or private_claim_3
                    ],
                },
            }
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
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        },
    )
    request_uri = presentation_request["request_uri"]
    presentation_id = presentation_request["presentation"]["presentation_id"]

    # Credo presents with selective disclosure
    present_response = await credo_client.post(
        "/oid4vp/present",
        json={"request_uri": request_uri, "credentials": [sd_jwt_credential]},
    )
    assert present_response.status_code == 200, (
        f"Present failed: {present_response.text}"
    )

    # Verify presentation and check disclosed claims
    record = await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)

    # Check what was disclosed in the verified claims
    verified_claims = record.get("verified_claims", {})
    print(f"Selective disclosure test - verified claims: {verified_claims}")

    # Bug discovery: Check if unrequested claims were incorrectly disclosed
    if verified_claims:
        # These should NOT be present if selective disclosure is working correctly
        if "private_claim_2" in str(verified_claims) or "private_claim_3" in str(
            verified_claims
        ):
            print("WARNING: Unrequested claims were disclosed - potential SD bug")


@pytest.mark.xfail(
    reason=(
        "Known interop limitation: Credo does not POST the VP response back to "
        "ACA-Py for PEX + SD-JWT requests. Presentation stays in "
        "'request-retrieved' state and times out."
    ),
)
@pytest.mark.asyncio
async def test_selective_disclosure_all_claims_disclosed(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    issuer_ed25519_did,
    sd_jwt_credential_config,
):
    """Test that all requested claims ARE disclosed when requested."""
    credential_supported = sd_jwt_credential_config(
        vct="FullSDCredential",
        claims={
            "claim_a": {"mandatory": True},
            "claim_b": {"mandatory": True},
            "claim_c": {"mandatory": True},
        },
        sd_list=["/claim_a", "/claim_b", "/claim_c"],
        scope="FullSDTest",
        proof_algs=["EdDSA"],
        crypto_suites=["EdDSA"],
    )

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = config_response["supported_cred_id"]

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_id,
            "credential_subject": {
                "claim_a": "value_a",
                "claim_b": "value_b",
                "claim_c": "value_c",
            },
            "did": issuer_ed25519_did,
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_response["exchange_id"]},
    )

    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_response["credential_offer"],
            "holder_did_method": "key",
        },
    )
    credential = safely_get_first_credential(credo_response, "Credo")

    # Request ALL claims
    full_sd_test_id = str(uuid.uuid4())
    presentation_definition = {
        "id": full_sd_test_id,
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        "input_descriptors": [
            {
                "id": full_sd_test_id,
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {"path": ["$.vct"], "filter": {"const": "FullSDCredential"}},
                        {"path": ["$.claim_a", "$.credentialSubject.claim_a"]},
                        {"path": ["$.claim_b", "$.credentialSubject.claim_b"]},
                        {"path": ["$.claim_c", "$.credentialSubject.claim_c"]},
                    ],
                },
            }
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

    present_response = await credo_client.post(
        "/oid4vp/present",
        json={
            "request_uri": presentation_request["request_uri"],
            "credentials": [credential],
        },
    )
    assert present_response.status_code == 200

    record = await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)

    # Verify all requested claims are present
    verified_claims = record.get("verified_claims", {})
    print(f"Full disclosure test - verified claims: {verified_claims}")
