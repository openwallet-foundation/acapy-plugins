"""Quick test script."""
import json
import pytest
import pytest_asyncio
from urllib.parse import urlencode
from os import getenv

from controller.controller import Controller
from controller.models import DIDResult
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


@pytest_asyncio.fixture
async def issuer_did(controller: Controller):
    result = await controller.post(
        "/wallet/did/create",
        json={
            "method": "key",
            "key_type": "ed25519",
        },
        response=DIDResult,
    )
    assert result.result
    did = result.result.did
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
    offer_uri = "openid-credential-offer://" + urlencode(
        {"credential_offer": json.dumps(offer)}
    )
    yield offer_uri


@pytest.mark.asyncio
async def test_pre_auth_code_flow_ed25519(client: OpenID4VCIClient, offer: str):
    """Connect to AFJ."""
    did = client.generate_did("ed25519")
    response = await client.receive_offer(offer, did)


@pytest.mark.asyncio
async def test_pre_auth_code_flow_secp256k1(client: OpenID4VCIClient, offer: str):
    """Connect to AFJ."""
    did = client.generate_did("secp256k1")
    response = await client.receive_offer(offer, did)
