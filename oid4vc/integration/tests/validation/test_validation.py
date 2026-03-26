"""Test validations in OID4VC."""

import uuid

import httpx
import pytest


@pytest.mark.asyncio
async def test_mso_mdoc_validation(acapy_issuer_admin):
    """Test that mso_mdoc rejects invalid configurations."""

    # 1. Test creating supported credential with invalid format_data
    # validate_supported_credential should fail
    random_suffix = str(uuid.uuid4())[:8]
    invalid_supported_cred = {
        "id": f"InvalidMDOC_{random_suffix}",
        "format": "mso_mdoc",
        "scope": "InvalidMDOC",
        "format_data": {},  # Missing doctype and other required fields
        "vc_additional_data": {},
    }

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=invalid_supported_cred
        )
    assert excinfo.value.response.status_code == 400

    # 2. Test creating exchange with invalid credential subject
    # validate_credential_subject should fail

    # Create a valid supported cred to proceed to exchange step
    # OID4VCI v1.0 compliant: include cryptographic_binding_methods_supported
    valid_supported_cred = {
        "id": f"ValidMDOC_{random_suffix}",
        "format": "mso_mdoc",
        "scope": "ValidMDOC",
        "format_data": {"doctype": "org.iso.18013.5.1.mDL"},
        "cryptographic_binding_methods_supported": ["cose_key"],
        "credential_signing_alg_values_supported": ["ES256"],
        "vc_additional_data": {},
    }
    response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=valid_supported_cred
    )
    config_id = response["supported_cred_id"]

    # Create a DID for the issuer first
    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    issuer_did = did_response["result"]["did"]

    exchange_request = {
        "supported_cred_id": config_id,
        "credential_subject": {},  # Empty subject, should be invalid
        "did": issuer_did,
    }

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        await acapy_issuer_admin.post("/oid4vci/exchange/create", json=exchange_request)
    assert excinfo.value.response.status_code == 400
