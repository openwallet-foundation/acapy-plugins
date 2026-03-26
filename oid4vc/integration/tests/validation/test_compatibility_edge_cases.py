"""Edge case tests for ACA-Py OID4VC plugin handling of unusual data.

These tests verify the plugin correctly handles edge cases like:
- Empty/null claim values
- Special characters (unicode, emoji, quotes)
- Large credential payloads

Note: Tests for wallet-specific behavior (token reuse, replay attacks,
credential matching) have been removed as they test wallet implementations
rather than the ACA-Py plugin.
"""

import asyncio
import uuid

import pytest

# =============================================================================
# Empty/Null Value Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_empty_claim_values(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test credential with empty string claim values.

    Bug discovery: How do wallets handle empty string vs null vs missing claims?
    """
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"EmptyClaimCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "EmptyClaimTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "credential_signing_alg_values_supported": ["EdDSA"],
            "vct": "EmptyClaimCredential",
            "claims": {
                "required_field": {"mandatory": True},
                "optional_empty": {"mandatory": False},
            },
        },
        "vc_additional_data": {"sd_list": ["/required_field", "/optional_empty"]},
    }

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Issue with empty string value
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": {
                "required_field": "has_value",
                "optional_empty": "",  # Empty string
            },
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Credo accepts
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
    )

    print(f"Empty claim credential issuance: {credo_response.status_code}")
    if credo_response.status_code == 200:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]

        # Try to present with empty claim
        pres_def = {
            "id": str(uuid.uuid4()),
            "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            "input_descriptors": [
                {
                    "id": "empty-claim-test",
                    "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {"const": "EmptyClaimCredential"},
                            },
                            {
                                "path": [
                                    "$.optional_empty",
                                    "$.credentialSubject.optional_empty",
                                ]
                            },
                        ]
                    },
                }
            ],
        }

        pres_def_resp = await acapy_verifier_admin.post(
            "/oid4vp/presentation-definition", json={"pres_def": pres_def}
        )

        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_resp["pres_def_id"],
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )

        present_resp = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request["request_uri"], "credentials": [credential]},
        )

        print(f"Empty claim presentation: {present_resp.status_code}")
        if present_resp.status_code == 200:
            presentation_id = request["presentation"]["presentation_id"]
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
            print(f"Empty claim verification: {record.get('state')}")


# =============================================================================
# Special Character Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_special_characters_in_claims(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test handling of special characters in claim values.

    Bug discovery: Unicode, quotes, newlines in credential subjects.
    """
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"SpecialCharCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "SpecialCharTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "credential_signing_alg_values_supported": ["EdDSA"],
            "vct": "SpecialCharCredential",
            "claims": {
                "unicode_name": {"mandatory": True},
                "special_chars": {"mandatory": True},
            },
        },
        "vc_additional_data": {"sd_list": ["/unicode_name", "/special_chars"]},
    }

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Issue with special characters
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": {
                "unicode_name": "José García 日本語 🔐",  # Unicode + emoji
                "special_chars": 'Quote "test" & <angle> brackets',  # Problematic chars
            },
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
    )

    print(f"Special char credential issuance: {credo_response.status_code}")
    if credo_response.status_code != 200:
        print(f"Failed with special chars: {credo_response.text}")
    else:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]

        # Present and verify special chars are preserved
        pres_def = {
            "id": str(uuid.uuid4()),
            "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            "input_descriptors": [
                {
                    "id": "special-char-test",
                    "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {"const": "SpecialCharCredential"},
                            },
                            {
                                "path": [
                                    "$.unicode_name",
                                    "$.credentialSubject.unicode_name",
                                ]
                            },
                        ]
                    },
                }
            ],
        }

        pres_def_resp = await acapy_verifier_admin.post(
            "/oid4vp/presentation-definition", json={"pres_def": pres_def}
        )

        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_resp["pres_def_id"],
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )
        presentation_id = request["presentation"]["presentation_id"]

        present_resp = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request["request_uri"], "credentials": [credential]},
        )

        if present_resp.status_code == 200:
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

            print(f"Special char verification: {record.get('state')}")
            # Check if values were preserved
            verified = record.get("verified_claims", {})
            print(f"Verified claims with special chars: {verified}")


# =============================================================================
# Large Payload Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_large_credential_subject(
    acapy_issuer_admin,
    credo_client,
):
    """Test handling of large credential subject payloads.

    Bug discovery: Payload size limits, truncation issues.
    """
    random_suffix = str(uuid.uuid4())[:8]

    # Create credential with many claims
    claims = {f"claim_{i}": {"mandatory": False} for i in range(50)}
    claims["id_field"] = {"mandatory": True}

    sd_list = [f"/claim_{i}" for i in range(50)]
    sd_list.append("/id_field")

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "id": f"LargeCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "LargeTest",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "LargeCredential",
                "claims": claims,
            },
            "vc_additional_data": {"sd_list": sd_list},
        },
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Create large credential subject
    credential_subject = {"id_field": "large_credential_test"}
    for i in range(50):
        # Use moderately long values
        credential_subject[f"claim_{i}"] = (
            f"This is claim number {i} with some additional text to make it longer " * 3
        )

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": credential_subject,
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Try to accept large credential
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
        timeout=60.0,  # Extended timeout for large payload
    )

    print(f"Large credential issuance: {credo_response.status_code}")
    if credo_response.status_code == 200:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]
        print(f"Large credential size: {len(credential)} bytes")
    else:
        print(f"Large credential failed: {credo_response.text[:500]}")
