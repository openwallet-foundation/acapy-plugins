"""Quick test script."""
import json
import pytest
import pytest_asyncio
from urllib.parse import urlencode
from os import getenv

from controller.controller import Controller
from oid4vci_client.client import OpenID4VCIClient

ISSUER_ADMIN_ENDPOINT = getenv("ISSUER_ADMIN_ENDPOINT", "http://localhost:3001")


@pytest_asyncio.fixture
async def controller():
    """Connect to Issuer."""
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with controller:
        yield controller


@pytest.fixture
def client():
    client = OpenID4VCIClient()
    yield client


@pytest.mark.asyncio
async def test_pre_auth_code_flow(controller: Controller, client: OpenID4VCIClient):
    """Connect to AFJ."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["EdDSA"],
            "format": "jwt_vc_json",
            "id": "UniversityDegreeCredential",
            "types": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_ubject": {"name": "alice"},
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = "openid-credential-offer://" + urlencode(
        {"credential_offer": json.dumps(offer)}
    )
    response = await client.receive_offer(offer_uri)
    print(response)
    assert False
