import json
from os import getenv
from urllib.parse import quote, urlencode

from acapy_controller.controller import Controller
import pytest
import pytest_asyncio

from oid4vci_client.client import OpenID4VCIClient

ISSUER_ADMIN_ENDPOINT = getenv("ISSUER_ADMIN_ENDPOINT", "http://localhost:3001")

@pytest_asyncio.fixture
async def controller():
    """Connect to Issuer."""
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with controller:
        yield controller


@pytest.fixture
def test_client():
    client = OpenID4VCIClient()
    yield client


@pytest_asyncio.fixture
async def issuer_did(controller: Controller):
    result = await controller.post(
        "/wallet/did/create",
        json={
            "method": "key",
            "key_type": "ed25519",
        },
    )
    assert "result" in result
    assert "did" in result["result"]
    did = result["result"]["did"]
    yield did


@pytest_asyncio.fixture
async def supported_cred_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["EdDSA"],
            "format": "jwt_vc_json",
            "id": "UniversityDegreeCredential",
            "format_data": {
                "types": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
            "vc_additional_data": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )
    yield supported["supported_cred_id"]


@pytest_asyncio.fixture
async def offer(controller: Controller, issuer_did: str, supported_cred_id: str):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "did": issuer_did,
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = "openid-credential-offer://?" + urlencode(
        {"credential_offer": json.dumps(offer)}, quote_via=quote
    )
    yield offer_uri
