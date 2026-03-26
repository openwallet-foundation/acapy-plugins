"""Cross-wallet Sphereon JWT compatibility tests for OID4VC.

These tests focus on Sphereon wallet behavior with JWT VC credentials:
1. Issuing JWT VCs to Sphereon and verifying with Credo-compatible patterns
2. Testing format support differences with Sphereon
3. Documenting known interoperability bugs between Sphereon and ACA-Py
"""

import asyncio

import pytest

from tests.conftest import safely_get_first_credential

# =============================================================================
# Cross-Wallet Issuance and Verification Tests - Sphereon Focus
# =============================================================================


@pytest.mark.asyncio
async def test_issue_to_sphereon_verify_with_credo_jwt_vc(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,  # noqa: ARG001
    sphereon_client,
    issuer_p256_did,
):
    """Issue JWT VC to Sphereon, then try to verify if Credo can handle similar patterns.

    This tests format compatibility between wallets for JWT VC credentials.
    """
    # Step 1: Issue JWT VC to Sphereon
    import uuid

    random_suffix = str(uuid.uuid4())[:8]
    cred_id = f"SphereonIssuedCredential-{random_suffix}"

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

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "sphereon_test_user"},
            "verification_method": issuer_p256_did + "#0",
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": credential_offer}
    )
    sphereon_credential = safely_get_first_credential(response, "Sphereon")

    # Step 2: Create presentation definition for JWT VP
    # NOTE: Using schema-based definition (like existing Sphereon tests)
    # instead of format+constraints pattern which may cause interop issues
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "input_descriptors": [
            {
                "id": "university_degree",
                "name": "University Degree",
                "schema": [{"uri": "https://www.w3.org/2018/credentials/examples/v1"}],
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
            "vp_formats": {"jwt_vp_json": {"alg": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]
    presentation_id = request_response["presentation"]["presentation_id"]

    # Step 3: Sphereon presents the credential
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_uri,
            "verifiable_credentials": [sphereon_credential],
        },
    )
    assert present_response.status_code == 200, (
        f"Sphereon present failed: {present_response.text}"
    )

    # Step 4: Verify on ACA-Py side
    record = None
    for _ in range(10):
        record = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )
        if record["state"] == "presentation-valid":
            break
        await asyncio.sleep(1)
    else:
        # Capture diagnostic info for debugging the interop bug
        error_info = {
            "state": record.get("state") if record else "no record",
            "errors": record.get("errors") if record else None,
            "verified": record.get("verified") if record else None,
        }
        pytest.fail(
            f"Sphereon JWT VP presentation rejected by ACA-Py verifier.\n"
            f"This is an interoperability bug between Sphereon and ACA-Py OID4VP.\n"
            f"Diagnostic info: {error_info}\n"
            f"Credential format: jwt_vc_json, VP format: jwt_vp_json"
        )


@pytest.mark.asyncio
async def test_sphereon_jwt_vp_with_constraints_pattern(
    acapy_issuer_admin,
    acapy_verifier_admin,
    sphereon_client,
    issuer_p256_did,
):
    """Test Sphereon JWT VP with format+constraints presentation definition.

    Uses 'format' and 'constraints' in input_descriptors (instead of 'schema'),
    which requires the verifier to evaluate constraint field paths against the
    decoded JWT VC payload.  The type field in a JWT VC lives at $.vc.type so
    the constraint path must include that alongside the legacy $.type fallback.
    """
    import uuid

    random_suffix = str(uuid.uuid4())[:8]
    cred_id = f"ConstraintsBugTest-{random_suffix}"

    # Issue JWT VC to Sphereon
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
            "type": ["VerifiableCredential", "TestCredential"],
        },
    )

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_subject": {"test": "value"},
            "verification_method": issuer_p256_did + "#0",
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": offer_response["credential_offer"]}
    )
    credential = safely_get_first_credential(response, "Sphereon")

    # Use format+constraints pattern (known to fail)
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "input_descriptors": [
            {
                "id": "test-descriptor",
                "name": "Test Credential",
                "format": {"jwt_vp_json": {"alg": ["ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            # JWT VCs embed 'type' inside the 'vc' claim of the
                            # JWT payload.  Include both paths so the constraint
                            # works whether the verifier returns the raw JWT
                            # payload ($.vc.type) or a flattened form ($.type).
                            "path": ["$.vc.type", "$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "TestCredential"},
                            },
                        },
                    ]
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )

    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_response["pres_def_id"],
            "vp_formats": {"jwt_vp_json": {"alg": ["ES256"]}},
        },
    )

    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_response["request_uri"],
            "verifiable_credentials": [credential],
        },
    )
    assert present_response.status_code == 200

    # Verify ACA-Py received and validated the presentation
    presentation_id = request_response["presentation"]["presentation_id"]
    for _ in range(10):
        record = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )
        if record["state"] == "presentation-valid":
            break
        await asyncio.sleep(1)
    else:
        pytest.fail(
            f"Presentation not validated. State: {record['state']}, "
            f"errors: {record.get('errors')}"
        )


# =============================================================================
# Format Negotiation Edge Cases - Sphereon Focus
# =============================================================================


@pytest.mark.asyncio
async def test_sphereon_unsupported_format_request(
    acapy_issuer_admin,
    acapy_verifier_admin,
    sphereon_client,
    issuer_p256_did,
):
    """Test Sphereon behavior when asked to present unsupported format.

    Issue JWT VC but request SD-JWT presentation format.
    """
    import uuid

    random_suffix = str(uuid.uuid4())[:8]
    cred_id = f"FormatTestCredential-{random_suffix}"

    # Issue JWT VC (not SD-JWT)
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "TestCredential"],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"test": "value"},
            "verification_method": issuer_p256_did + "#0",
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Sphereon accepts JWT VC
    response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": offer_response["credential_offer"]}
    )
    jwt_credential = safely_get_first_credential(response, "Sphereon")

    # Create request for SD-JWT format (mismatched)
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},  # SD-JWT, not JWT VC
        "input_descriptors": [
            {
                "id": "format-test",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
                "constraints": {"fields": [{"path": ["$.vct"]}]},
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
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]

    # Attempt to present JWT VC as SD-JWT - should fail
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_uri,
            "verifiable_credentials": [jwt_credential],
        },
    )

    # Document behavior for bug discovery
    print(f"Format mismatch test: Sphereon returned {present_response.status_code}")
    if present_response.status_code == 200:
        print("WARNING: Sphereon accepted format mismatch - potential interop issue")
    else:
        print(f"Sphereon correctly rejected: {present_response.text}")
