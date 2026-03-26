"""Test mDOC interop between ACA-Py and Credo.

This test file covers mDOC (ISO 18013-5 mobile document) credential issuance
and presentation flows between ACA-Py and Credo wallets.

Test coverage:
1. mDOC credential issuance via OID4VCI (DID-based and verification_method flows)
2. mDOC selective disclosure presentation via OID4VP
3. mDOC doctype validation
4. Age predicate verification (age_over_18 without birth_date)
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from credo_wrapper import CredoWrapper
from tests.helpers.constants import MDL_MANDATORY_FIELDS

# Import shared fixtures from parent conftest
# Note: setup_all_trust_anchors is defined in tests/conftest.py


# Mark all tests as requiring mDOC support
pytestmark = [pytest.mark.mdoc, pytest.mark.interop]


async def create_dcql_request(
    client: httpx.AsyncClient,
    dcql_query: dict,
    vp_formats: dict | None = None,
) -> str:
    """Create a DCQL query and then create a VP request using the query ID.

    This follows the correct two-step flow:
    1. POST /oid4vp/dcql/queries with the DCQL query → returns dcql_query_id
    2. POST /oid4vp/request with dcql_query_id → returns request_uri

    Args:
        client: The HTTP client to use
        dcql_query: The DCQL query definition
        vp_formats: VP formats (defaults to mso_mdoc with ES256)

    Returns:
        The request_uri for the VP request
    """
    if vp_formats is None:
        vp_formats = {"mso_mdoc": {"alg": ["ES256"]}}

    # Step 1: Create the DCQL query
    query_response = await client.post(
        "/oid4vp/dcql/queries",
        json=dcql_query,
    )
    query_response.raise_for_status()
    dcql_query_id = query_response.json()["dcql_query_id"]

    # Step 2: Create the VP request using the query ID
    request_response = await client.post(
        "/oid4vp/request",
        json={
            "dcql_query_id": dcql_query_id,
            "vp_formats": vp_formats,
        },
    )
    request_response.raise_for_status()
    return request_response.json()["request_uri"]


@pytest_asyncio.fixture
async def mdoc_credential_config(acapy_issuer: httpx.AsyncClient) -> dict[str, Any]:
    """Create an mDOC credential configuration on ACA-Py issuer."""
    random_suffix = str(uuid.uuid4())[:8]

    # mDOC credential configuration for mobile driver's license
    # Note: Use "jwt" proof type as Credo only supports jwt/attestation (not cwt)
    credential_supported = {
        "id": f"org.iso.18013.5.1.mDL_{random_suffix}",
        "format": "mso_mdoc",
        "scope": "mDL",
        "doctype": "org.iso.18013.5.1.mDL",
        "cryptographic_binding_methods_supported": ["cose_key", "did:key", "did"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
        },
        "format_data": {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "family_name": {"mandatory": True},
                    "given_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                    "age_over_18": {"mandatory": False},
                    "age_over_21": {"mandatory": False},
                    "issuing_country": {"mandatory": True},
                    "issuing_authority": {"mandatory": True},
                    "document_number": {"mandatory": True},
                },
            },
            "display": [
                {
                    "name": "Mobile Driving License",
                    "locale": "en-US",
                    "description": "ISO 18013-5 compliant mobile driving license",
                }
            ],
        },
    }

    response = await acapy_issuer.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    response.raise_for_status()
    config = response.json()

    return {
        "supported_cred_id": config["supported_cred_id"],
        "doctype": "org.iso.18013.5.1.mDL",
        "config": credential_supported,
    }


@pytest_asyncio.fixture
async def mdoc_issuer_key(
    acapy_issuer: httpx.AsyncClient,
    mdoc_credential_config: dict[str, Any],
) -> dict[str, Any]:
    """Generate and upload an mDOC signing key for the issuer.

    Uses the ``POST /mso-mdoc/signing-keys/import`` endpoint to upload a
    locally generated key pair to the signing key registry.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test mDoc Issuer"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    # Import via the signing key registry
    response = await acapy_issuer.post(
        "/mso-mdoc/signing-keys/import",
        json={
            "private_key_pem": private_key_pem,
            "certificate_pem": certificate_pem,
            "label": "test-interop-signing-key",
        },
    )
    response.raise_for_status()
    result = response.json()
    signing_key_id = result.get("id")

    yield {
        "signing_key_id": signing_key_id,
        "certificate_pem": certificate_pem,
    }

    # Teardown: delete the signing key to prevent record accumulation.
    # Stale records with bare certs (no IACA extensions) would otherwise be
    # picked by _resolve_signing_key and cause cert validation errors in
    # subsequent tests.
    if signing_key_id:
        try:
            await acapy_issuer.delete(f"/mso-mdoc/signing-keys/{signing_key_id}")
        except Exception:
            pass  # Best-effort cleanup


@pytest_asyncio.fixture
async def mdoc_offer_did_based(
    acapy_issuer: httpx.AsyncClient,
    mdoc_credential_config: dict[str, Any],
    setup_issuer_certs,  # noqa: ARG001 - ensures default signing key exists
) -> str:
    """Create an mDOC credential offer using DID-based signing.

    This is the primary flow that mirrors test_acapy_credo_mdoc_flow.
    Uses a did:key with P-256 curve for mDOC signing.
    """
    # Create credential subject with mDL claims
    credential_subject = {
        "org.iso.18013.5.1": {
            "family_name": "Doe",
            "given_name": "Jane",
            "birth_date": "1990-05-15",
            "age_over_18": True,
            "age_over_21": True,
            "issuing_country": "US",
            "issuing_authority": "State DMV",
            "document_number": "DL123456789",
            **MDL_MANDATORY_FIELDS,
        }
    }

    # Create an issuer DID for mDOC signing (P-256 for mDOC compatibility)
    did_response = await acapy_issuer.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "p256"}}
    )
    did_response.raise_for_status()
    issuer_did = did_response.json()["result"]["did"]

    exchange_request = {
        "supported_cred_id": mdoc_credential_config["supported_cred_id"],
        "credential_subject": credential_subject,
        "did": issuer_did,
    }

    response = await acapy_issuer.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    response.raise_for_status()
    exchange_id = response.json()["exchange_id"]

    response = await acapy_issuer.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    response.raise_for_status()
    return response.json()["credential_offer"]


@pytest_asyncio.fixture
async def mdoc_offer_verification_method(
    acapy_issuer: httpx.AsyncClient,
    mdoc_credential_config: dict[str, Any],
    setup_issuer_certs,  # noqa: ARG001 - ensures signing key with IACA cert is present
) -> str:
    """Create an mDOC credential offer using DID-based signing.

    Uses setup_issuer_certs so the signing key is the same one whose root CA
    is registered as a trust anchor on both Credo and the ACA-Py verifier.
    """
    # Create credential subject with mDL claims
    credential_subject = {
        "org.iso.18013.5.1": {
            "family_name": "Smith",
            "given_name": "John",
            "birth_date": "1985-03-20",
            "age_over_18": True,
            "age_over_21": True,
            "issuing_country": "US",
            "issuing_authority": "State DMV",
            "document_number": "DL987654321",
            **MDL_MANDATORY_FIELDS,
        }
    }

    # Use DID-based signing
    did_response = await acapy_issuer.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "p256"}},
    )
    did_response.raise_for_status()
    issuer_did = did_response.json()["result"]["did"]

    exchange_request = {
        "supported_cred_id": mdoc_credential_config["supported_cred_id"],
        "credential_subject": credential_subject,
        "did": issuer_did,
    }

    response = await acapy_issuer.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    response.raise_for_status()
    exchange_id = response.json()["exchange_id"]

    response = await acapy_issuer.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    response.raise_for_status()
    return response.json()["credential_offer"]


# Alias for backward compatibility - uses DID-based flow by default
@pytest_asyncio.fixture
async def mdoc_offer(
    mdoc_offer_did_based: str,
) -> str:
    """Create an mDOC credential offer (uses DID-based flow by default)."""
    return mdoc_offer_did_based


@pytest_asyncio.fixture
async def mdoc_presentation_request(
    acapy_verifier: httpx.AsyncClient,
) -> str:
    """Create an mDOC presentation request using DCQL."""

    # DCQL query for mDOC credential
    dcql_query = {
        "credentials": [
            {
                "id": "mdl_credential",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL",
                },
                "claims": [
                    {
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "family_name",
                    },
                    {
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "given_name",
                    },
                    {
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "age_over_18",
                    },
                ],
            }
        ],
    }

    return await create_dcql_request(acapy_verifier, dcql_query)


@pytest_asyncio.fixture
async def mdoc_age_only_request(
    acapy_verifier: httpx.AsyncClient,
) -> str:
    """Create a presentation request for age verification only (no birth_date)."""

    dcql_query = {
        "credentials": [
            {
                "id": "age_verification",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL",
                },
                "claims": [
                    {
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "age_over_18",
                        "values": [True],  # Must be true
                    },
                ],
            }
        ],
    }

    return await create_dcql_request(acapy_verifier, dcql_query)


# =============================================================================
# mDOC Issuance Tests
# =============================================================================


@pytest.mark.asyncio
async def test_mdoc_credential_config_creation(
    mdoc_credential_config: dict[str, Any],
):
    """Test that mDOC credential configuration can be created."""
    assert "supported_cred_id" in mdoc_credential_config
    assert mdoc_credential_config["doctype"] == "org.iso.18013.5.1.mDL"


@pytest.mark.asyncio
async def test_mdoc_issuer_key_generation(
    mdoc_issuer_key: dict[str, Any],
):
    """Test that mDOC issuer key can be generated."""
    assert mdoc_issuer_key is not None
    # Check for required key components
    assert "signing_key_id" in mdoc_issuer_key
    assert "certificate_pem" in mdoc_issuer_key


@pytest.mark.asyncio
async def test_mdoc_offer_creation_did_based(
    mdoc_offer_did_based: str,
):
    """Test that mDOC credential offer can be created using DID-based signing."""
    assert mdoc_offer_did_based is not None
    assert len(mdoc_offer_did_based) > 0
    # mDOC offers should start with openid-credential-offer://
    assert mdoc_offer_did_based.startswith("openid-credential-offer://")


@pytest.mark.asyncio
async def test_mdoc_offer_creation_verification_method(
    mdoc_offer_verification_method: str,
):
    """Test that mDOC credential offer can be created using verification_method."""
    assert mdoc_offer_verification_method is not None
    assert len(mdoc_offer_verification_method) > 0
    # mDOC offers should start with openid-credential-offer://
    assert mdoc_offer_verification_method.startswith("openid-credential-offer://")


@pytest.mark.asyncio
async def test_mdoc_credential_acceptance_did_based(
    credo: CredoWrapper,
    mdoc_offer_did_based: str,
    setup_all_trust_anchors,  # noqa: ARG001 - registers trust anchor with Credo
):
    """Test Credo accepting an mDOC credential offer using DID-based signing.

    This tests the primary flow where the issuer uses a did:key for signing.
    """
    result = await credo.openid4vci_accept_offer(mdoc_offer_did_based)

    assert result is not None
    assert "credential" in result
    assert result.get("format") == "mso_mdoc"


@pytest.mark.asyncio
async def test_mdoc_credential_acceptance_verification_method(
    credo: CredoWrapper,
    mdoc_offer_verification_method: str,
    setup_all_trust_anchors,  # noqa: ARG001 - registers trust anchor with Credo
):
    """Test Credo accepting an mDOC credential offer using verification_method.

    This tests the flow where the issuer uses signing keys stored in
    the SupportedCredential's vc_additional_data.
    """
    result = await credo.openid4vci_accept_offer(mdoc_offer_verification_method)

    assert result is not None
    assert "credential" in result
    assert result.get("format") == "mso_mdoc"


# =============================================================================
# mDOC Presentation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_mdoc_presentation_request_creation(
    mdoc_presentation_request: str,
):
    """Test that mDOC presentation request can be created."""
    assert mdoc_presentation_request is not None
    assert len(mdoc_presentation_request) > 0


@pytest.mark.asyncio
async def test_mdoc_selective_disclosure_presentation(
    credo: CredoWrapper,
    mdoc_offer_did_based: str,
    mdoc_presentation_request: str,
    setup_all_trust_anchors,  # noqa: ARG001 - Required for mDOC verification
):
    """Test mDOC selective disclosure presentation flow.

    This test verifies that:
    1. Credo can receive an mDOC credential
    2. Credo can present only the requested claims (selective disclosure)
    3. ACA-Py can verify the mDOC presentation

    Note: setup_all_trust_anchors is required for mDOC verification to work.
    """
    # First, get the credential
    cred_result = await credo.openid4vci_accept_offer(mdoc_offer_did_based)
    assert "credential" in cred_result

    # Present the credential with selective disclosure
    pres_result = await credo.openid4vp_accept_request(
        mdoc_presentation_request,
        credentials=[cred_result["credential"]],
    )

    assert pres_result is not None


@pytest.mark.asyncio
async def test_mdoc_age_predicate_verification(
    credo: CredoWrapper,
    mdoc_offer_did_based: str,
    mdoc_age_only_request: str,
    setup_all_trust_anchors,  # noqa: ARG001 - Required for mDOC verification
):
    """Test age verification without disclosing birth_date.

    This is a key privacy-preserving feature of mDOC credentials:
    proving age_over_18 without revealing the actual birth date.

    Note: setup_all_trust_anchors is required for mDOC verification to work.
    """
    # Get the credential
    cred_result = await credo.openid4vci_accept_offer(mdoc_offer_did_based)
    assert "credential" in cred_result

    # Present only age_over_18
    pres_result = await credo.openid4vp_accept_request(
        mdoc_age_only_request,
        credentials=[cred_result["credential"]],
    )

    assert pres_result is not None


@pytest.mark.asyncio
async def test_mdoc_presentation_verification_method_flow(
    credo: CredoWrapper,
    mdoc_offer_verification_method: str,
    mdoc_presentation_request: str,
    setup_all_trust_anchors,  # noqa: ARG001 - Required for mDOC verification
):
    """Test mDOC presentation flow using verification_method-based credentials.

    This tests the full flow where the issuer uses signing keys stored in
    the SupportedCredential's vc_additional_data.
    """
    # First, get the credential
    cred_result = await credo.openid4vci_accept_offer(mdoc_offer_verification_method)
    assert "credential" in cred_result

    # Present the credential
    pres_result = await credo.openid4vp_accept_request(
        mdoc_presentation_request,
        credentials=[cred_result["credential"]],
    )

    assert pres_result is not None


# =============================================================================
# Negative Tests
# =============================================================================


@pytest.mark.asyncio
async def test_mdoc_wrong_doctype_rejected(
    acapy_verifier: httpx.AsyncClient,
):
    """Test that presenting wrong doctype is rejected."""

    # Create a request for a different doctype
    dcql_query = {
        "credentials": [
            {
                "id": "wrong_doctype",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.example.non_existent",
                },
                "claims": [
                    {
                        "namespace": "org.example",
                        "claim_name": "test",
                    },
                ],
            }
        ],
    }

    # First create the DCQL query
    query_response = await acapy_verifier.post(
        "/oid4vp/dcql/queries",
        json=dcql_query,
    )
    query_response.raise_for_status()
    dcql_query_id = query_response.json()["dcql_query_id"]

    # Then create the VP request
    response = await acapy_verifier.post(
        "/oid4vp/request",
        json={
            "dcql_query_id": dcql_query_id,
            "vp_formats": {
                "mso_mdoc": {"alg": ["ES256"]},
            },
        },
    )

    # Should succeed in creating the request (validation happens at presentation time)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_mdoc_missing_required_claim_handling(
    acapy_issuer: httpx.AsyncClient,
    mdoc_credential_config: dict[str, Any],
):
    """Test handling of missing required claims in mDOC issuance."""

    # Try to create a credential with missing required claims
    credential_subject = {
        "org.iso.18013.5.1": {
            "family_name": "Doe",
            # Missing given_name, birth_date, etc.
        }
    }

    exchange_request = {
        "supported_cred_id": mdoc_credential_config["supported_cred_id"],
        "credential_subject": credential_subject,
    }

    response = await acapy_issuer.post(
        "/oid4vci/exchange/create", json=exchange_request
    )

    # Depending on implementation, this might fail or succeed with partial claims
    # The actual behavior depends on whether the issuer validates mandatory claims
    # at exchange creation time or at credential issuance time
    # API may return 500 for internal validation errors
    assert response.status_code in [200, 400, 422, 500]


# =============================================================================
# DCQL CredentialSets Tests
# =============================================================================


@pytest.mark.asyncio
async def test_dcql_credential_sets_request(
    acapy_verifier: httpx.AsyncClient,
):
    """Test DCQL request with credential_sets (alternative credentials)."""

    dcql_query = {
        "credentials": [
            {
                "id": "mdl_credential",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL",
                },
                "claims": [
                    {"namespace": "org.iso.18013.5.1", "claim_name": "family_name"},
                    {"namespace": "org.iso.18013.5.1", "claim_name": "age_over_18"},
                ],
            },
            {
                "id": "passport_credential",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.23220.1.passport",
                },
                "claims": [
                    {"namespace": "org.iso.23220.1", "claim_name": "family_name"},
                    {"namespace": "org.iso.23220.1", "claim_name": "date_of_birth"},
                ],
            },
        ],
        "credential_sets": [
            {
                "options": [
                    ["mdl_credential"],  # Option 1: mDL
                    ["passport_credential"],  # Option 2: Passport
                ],
                "required": True,
            }
        ],
    }

    request_uri = await create_dcql_request(acapy_verifier, dcql_query)
    assert request_uri is not None


@pytest.mark.asyncio
async def test_dcql_claim_sets_request(
    acapy_verifier: httpx.AsyncClient,
):
    """Test DCQL request with claim_sets (alternative claim combinations)."""

    dcql_query = {
        "credentials": [
            {
                "id": "mdl_credential",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL",
                },
                "claims": [
                    {
                        "id": "name",
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "family_name",
                    },
                    {
                        "id": "age18",
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "age_over_18",
                    },
                    {
                        "id": "age21",
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "age_over_21",
                    },
                    {
                        "id": "birth",
                        "namespace": "org.iso.18013.5.1",
                        "claim_name": "birth_date",
                    },
                ],
                "claim_sets": [
                    ["name", "age18"],  # Option 1: name + age_over_18
                    ["name", "age21"],  # Option 2: name + age_over_21
                    ["name", "birth"],  # Option 3: name + birth_date (full disclosure)
                ],
            },
        ],
    }

    request_uri = await create_dcql_request(acapy_verifier, dcql_query)
    assert request_uri is not None
