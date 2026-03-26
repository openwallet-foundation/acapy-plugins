import uuid
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from aiohttp import ClientSession


@pytest_asyncio.fixture
async def issuer_did(acapy_issuer_admin):
    result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={
            "key_type": "p256",
        },
    )
    assert "did" in result
    yield result["did"]


@pytest_asyncio.fixture
async def supported_cred_id(acapy_issuer_admin, issuer_did):
    """Create a supported credential."""
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
    yield supported["supported_cred_id"]


@pytest.mark.asyncio
async def test_credential_offer_structure(
    acapy_issuer_admin, issuer_did, supported_cred_id
):
    """Test that the credential offer endpoint returns the correct structure."""
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

    # Verify structure
    assert "offer" in offer_response
    assert "credential_offer" in offer_response
    assert isinstance(offer_response["offer"], dict)
    assert isinstance(offer_response["credential_offer"], str)
    assert offer_response["credential_offer"].startswith("openid-credential-offer://")


@pytest.mark.asyncio
async def test_credential_offer_by_ref_structure(
    acapy_issuer_admin, issuer_did, supported_cred_id
):
    """Test that the credential offer by ref endpoint returns the correct structure."""
    # Create exchange
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

    # Verify structure
    assert "offer" in offer_response
    assert "credential_offer_uri" in offer_response
    assert isinstance(offer_response["offer"], dict)
    assert isinstance(offer_response["credential_offer_uri"], str)
    assert offer_response["credential_offer_uri"].startswith(
        "openid-credential-offer://"
    )

    # Verify dereferencing
    offer_uri_parsed = urlparse(offer_response["credential_offer_uri"])
    offer_ref_url = parse_qs(offer_uri_parsed.query)["credential_offer"][0]
    # Replace internal docker hostname with localhost for test execution
    # offer_ref_url = offer_ref_url.replace("acapy-issuer.local", "localhost")

    # We need to make a request to the dereference URL.
    # Since acapy_issuer_admin is a Controller which wraps a client, we can use it if the URL is relative or absolute.
    # The URL returned is likely absolute.

    # We can use aiohttp directly or try to use the controller if it supports full URLs.
    # Let's use aiohttp ClientSession for the dereference request to be safe and independent.

    async with ClientSession() as session:
        async with session.get(offer_ref_url) as resp:
            assert resp.status == 200
            dereferenced_offer = await resp.json()

            assert "offer" in dereferenced_offer
            assert "credential_offer" in dereferenced_offer
            assert isinstance(dereferenced_offer["offer"], dict)
            assert isinstance(dereferenced_offer["credential_offer"], str)
            assert dereferenced_offer["credential_offer"].startswith(
                "openid-credential-offer://"
            )
