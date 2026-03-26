import base64
import gzip
import logging
import uuid

import httpx
import jwt
import pytest
from bitarray import bitarray

from tests.conftest import wait_for_presentation_valid
from tests.helpers import MDOC_AVAILABLE
from tests.helpers.constants import MDL_MANDATORY_FIELDS

LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_sphereon_health(sphereon_client):
    """Test that Sphereon wrapper is healthy."""
    response = await sphereon_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_sphereon_accept_credential_offer(acapy_issuer_admin, sphereon_client):
    """Test Sphereon accepting a credential offer from ACA-Py."""

    # 1. Setup Issuer (ACA-Py)
    # Create a supported credential
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

    # 2. Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    print(f"Received credential: {result['credential']}")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_sphereon_accept_mdoc_credential_offer(
    acapy_issuer_admin,
    sphereon_client,
    setup_issuer_certs,  # noqa: ARG001 - ensures default signing key exists
):
    """Test Sphereon accepting an mdoc credential offer from ACA-Py."""

    # 1. Setup Issuer (ACA-Py)
    cred_id = f"mDL-{uuid.uuid4()}"

    # Create mdoc supported credential
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": ["ES256", "ES384", "ES512"],
            "format": "mso_mdoc",
            "id": cred_id,
            "identifier": "org.iso.18013.5.1.mDL",
            "format_data": {"doctype": "org.iso.18013.5.1.mDL"},
            "display": [
                {
                    "name": "Mobile Driver's License",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://example.com/mdl-logo.png",
                        "alt_text": "mDL Logo",
                    },
                    "background_color": "#003f7f",
                    "text_color": "#ffffff",
                }
            ],
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {
                        "mandatory": True,
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "birth_date": {
                        "mandatory": True,
                        "display": [{"name": "Date of Birth", "locale": "en-US"}],
                    },
                }
            },
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
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "birth_date": "1990-01-01",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # 2. Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer, "format": "mso_mdoc"},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    print(f"Received mdoc credential: {result['credential']}")

    # Verify the credential using isomdl_uniffi
    if MDOC_AVAILABLE:
        import isomdl_uniffi as mdl

        # Parse the credential
        mdoc_b64 = result["credential"]

        key_alias = "parsed"
        mdoc = mdl.Mdoc.new_from_base64url_encoded_issuer_signed(mdoc_b64, key_alias)

        # Verify issuer signature (if we had the issuer's cert/key, we could verify it fully)
        # For now, just checking we can parse it and get the doctype/id is a good step
        assert mdoc.doctype() == "org.iso.18013.5.1.mDL"
        assert mdoc.id() is not None

        print(f"Verified mdoc parsing: {mdoc.doctype()} / {mdoc.id()}")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_sphereon_present_mdoc_credential(
    acapy_verifier_admin,
    acapy_issuer_admin,
    sphereon_client,
    setup_all_trust_anchors,  # noqa: ARG001 - registers trust anchor with ACA-Py verifier
):
    """Test Sphereon presenting an mdoc credential to ACA-Py."""

    # 1. Issue a credential first (reuse setup from previous test or create new)
    cred_id = f"mDL-{uuid.uuid4()}"

    # Create mdoc supported credential
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
            "display": [{"name": "mDL", "locale": "en-US"}],
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                }
            },
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
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "birth_date": "1990-01-01",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer, "format": "mso_mdoc"},
    )
    assert response.status_code == 200
    credential_hex = response.json()["credential"]

    # 2. Create Presentation Request (ACA-Py Verifier)
    # Create presentation definition
    pres_def_id = str(uuid.uuid4())
    presentation_definition = {
        "id": pres_def_id,
        "input_descriptors": [
            {
                "id": "mdl",
                "name": "Mobile Driver's License",
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

    # Create request
    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]
    presentation_id = request_response["presentation"]["presentation_id"]

    # 3. Sphereon presents credential
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_uri,
            "verifiable_credentials": [credential_hex],
        },
    )

    assert present_response.status_code == 200

    # 4. Verify status on ACA-Py side
    await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)


@pytest.mark.asyncio
async def test_sphereon_accept_credential_offer_by_ref(
    acapy_issuer_admin, sphereon_client
):
    """Test Sphereon accepting a credential offer by reference from ACA-Py."""

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

    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer by ref
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer-by-ref",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer_uri = offer_response["credential_offer_uri"]

    # 2. Sphereon accepts offer
    # The Sphereon client library should handle dereferencing the URI
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer_uri},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result


# =============================================================================
# Revocation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_sphereon_revocation_flow(
    acapy_issuer_admin,
    sphereon_client,
):
    """Test revocation flow with Sphereon agent.

    1. Setup Issuer with Status List.
    2. Issue credential to Sphereon.
    3. Revoke credential.
    4. Verify status list is updated.
    """
    LOGGER.info("Starting Sphereon revocation flow test...")

    # 1. Setup Issuer
    cred_id = f"RevocableCredSphereon-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did:key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "display": [
                {
                    "name": "Revocable Credential Sphereon",
                    "locale": "en-US",
                }
            ],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "ed25519"}},
    )
    issuer_did = did_result["result"]["did"]

    # Create Status List Definition
    status_def = await acapy_issuer_admin.post(
        "/status-list/defs",
        json={
            "supported_cred_id": supported_cred_id,
            "status_purpose": "revocation",
            "list_size": 1024,
            "list_type": "w3c",
            "issuer_did": issuer_did,
        },
    )
    definition_id = status_def["id"]

    # 2. Issue Credential to Sphereon
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "Bob"},
            "did": issuer_did,
        },
    )
    exchange_id = exchange["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_id},
    )
    credential_offer = offer_response["credential_offer"]

    # Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer},
    )
    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    credential_jwt = result["credential"]

    # Verify credential has status list
    payload = jwt.decode(credential_jwt, options={"verify_signature": False})
    vc = payload.get("vc", payload)
    assert "credentialStatus" in vc

    # Check for bitstring format
    credential_status = vc["credentialStatus"]
    assert credential_status["type"] == "BitstringStatusListEntry"
    assert "id" in credential_status

    # Extract index from id (format: url#index)
    status_list_index = int(credential_status["id"].split("#")[1])
    status_list_url = credential_status["id"].split("#")[0]

    # Fix hostname for docker network if needed
    if "acapy-issuer.local" in status_list_url:
        status_list_url = status_list_url.replace("acapy-issuer.local", "acapy-issuer")
    elif "localhost" in status_list_url:
        status_list_url = status_list_url.replace("localhost", "acapy-issuer")

    LOGGER.info(f"Credential issued with status list index: {status_list_index}")

    # 3. Revoke Credential
    LOGGER.info(f"Revoking credential with ID: {exchange_id}")

    await acapy_issuer_admin.patch(
        f"/status-list/defs/{definition_id}/creds/{exchange_id}", json={"status": "1"}
    )

    # Publish update
    await acapy_issuer_admin.put(f"/status-list/defs/{definition_id}/publish")

    # 4. Verify Status List Updated
    async with httpx.AsyncClient() as client:
        response = await client.get(status_list_url)
        assert response.status_code == 200
        status_list_jwt = response.text

        sl_payload = jwt.decode(status_list_jwt, options={"verify_signature": False})

        # W3C format
        encoded_list = sl_payload["vc"]["credentialSubject"]["encodedList"]

        # Decode bitstring
        missing_padding = len(encoded_list) % 4
        if missing_padding:
            encoded_list += "=" * (4 - missing_padding)

        compressed_bytes = base64.urlsafe_b64decode(encoded_list)
        bit_bytes = gzip.decompress(compressed_bytes)

        ba = bitarray()
        ba.frombytes(bit_bytes)

        assert ba[status_list_index] == 1, "Bit should be set to 1 (revoked)"
        LOGGER.info("Revocation verified successfully for Sphereon flow")
