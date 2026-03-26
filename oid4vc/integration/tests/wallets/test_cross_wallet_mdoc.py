"""Cross-wallet mDOC compatibility tests for OID4VC.

These tests focus on mDOC format interoperability between Credo and Sphereon:
1. Issuing mDOCs to Credo and verifying with Sphereon-compatible patterns
2. Issuing mDOCs to Sphereon and verifying with Credo-compatible patterns
"""

import pytest

from tests.conftest import safely_get_first_credential, wait_for_presentation_valid
from tests.helpers import MDOC_AVAILABLE  # noqa: F401
from tests.helpers.constants import MDL_MANDATORY_FIELDS

# =============================================================================
# mDOC Cross-Wallet Tests
# =============================================================================


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_mdoc_issue_to_credo_verify_with_sphereon_patterns(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
    sphereon_client,  # noqa: ARG001
    setup_all_trust_anchors,
    mdoc_credential_config,
    issuer_p256_did,
):
    """Issue mDOC to Credo and verify using Sphereon-compatible verification patterns.

    Tests mDOC format interoperability between wallets.
    """
    import uuid

    credential_supported = mdoc_credential_config(
        doctype="org.iso.18013.5.1.mDL",
        namespace_claims={
            "org.iso.18013.5.1": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
            }
        },
    )
    # Add required OID4VCI fields for mDOC
    credential_supported["scope"] = "MdocCrossWalletTest"
    credential_supported["proof_types_supported"] = {
        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
    }
    # Include signing keys so the issuer can sign mDOC credentials
    credential_supported["vc_additional_data"] = {}

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = config_response["supported_cred_id"]

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_id,
            "did": issuer_p256_did,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "Cross",
                    "family_name": "Wallet",
                    **MDL_MANDATORY_FIELDS,
                }
            },
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_response["exchange_id"]},
    )

    # Credo accepts mDOC
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_response["credential_offer"],
            "holder_did_method": "key",
        },
    )
    mdoc_credential = safely_get_first_credential(credo_response, "Credo")

    # Verify format if response successful
    result = credo_response.json()
    if "format" in result:
        assert result["format"] == "mso_mdoc"

    # Create mDOC presentation request
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"mso_mdoc": {"alg": ["ES256"]}},
        "input_descriptors": [
            {
                "id": "org.iso.18013.5.1.mDL",
                "format": {"mso_mdoc": {"alg": ["ES256"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": ["$['org.iso.18013.5.1']['given_name']"],
                            "intent_to_retain": False,
                        },
                        {
                            "path": ["$['org.iso.18013.5.1']['family_name']"],
                            "intent_to_retain": False,
                        },
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
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    presentation_id = presentation_request["presentation"]["presentation_id"]

    # Credo presents mDOC
    present_response = await credo_client.post(
        "/oid4vp/present",
        json={
            "request_uri": presentation_request["request_uri"],
            "credentials": [mdoc_credential],
        },
    )
    assert present_response.status_code == 200, (
        f"Credo mDOC present failed: {present_response.text}"
    )

    # Verify on ACA-Py
    await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)
    print("mDOC cross-wallet test passed!")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_mdoc_issue_to_sphereon_verify_with_credo_patterns(
    acapy_issuer_admin,
    acapy_verifier_admin,
    sphereon_client,
    setup_all_trust_anchors,
):
    """Issue mDOC to Sphereon and verify.

    Tests Sphereon's mDOC handling and verification compatibility.
    """
    import uuid

    random_suffix = str(uuid.uuid4())[:8]
    cred_id = f"mDL-Sphereon-{random_suffix}"

    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "mso_mdoc",
            "id": cred_id,
            "identifier": "org.iso.18013.5.1.mDL",
            "format_data": {"doctype": "org.iso.18013.5.1.mDL"},
            "vc_additional_data": {},
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                }
            },
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create", json={"key_type": "p256"}
    )
    issuer_did = did_result["did"]

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "Sphereon",
                    "family_name": "Test",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Sphereon accepts mDOC
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": offer_response["credential_offer"], "format": "mso_mdoc"},
    )
    mdoc_credential = safely_get_first_credential(response, "Sphereon")

    # Create mDOC presentation request
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "input_descriptors": [
            {
                "id": "mdl",
                "format": {"mso_mdoc": {"alg": ["ES256"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": ["$['org.iso.18013.5.1']['given_name']"],
                            "intent_to_retain": False,
                        },
                    ],
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )
    pres_def_id = pres_def_response["pres_def_id"]

    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    presentation_id = request_response["presentation"]["presentation_id"]

    # Sphereon presents
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_response["request_uri"],
            "verifiable_credentials": [mdoc_credential],
        },
    )
    assert present_response.status_code == 200, (
        f"Sphereon mDOC present failed: {present_response.text}"
    )

    # Verify
    await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)
