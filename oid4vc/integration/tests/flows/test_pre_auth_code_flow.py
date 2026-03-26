"""Quick test script."""

import pytest

from oid4vci_client.client import OpenID4VCIClient


@pytest.fixture
def test_client():
    return OpenID4VCIClient()


@pytest.mark.asyncio
async def test_pre_auth_code_flow_ed25519(test_client: OpenID4VCIClient, offer: dict):
    """Connect to AFJ."""
    did = test_client.generate_did("ed25519")
    await test_client.receive_offer(offer["credential_offer"], did)


@pytest.mark.asyncio
async def test_pre_auth_code_flow_secp256k1(test_client: OpenID4VCIClient, offer: dict):
    """Connect to AFJ."""
    did = test_client.generate_did("secp256k1")
    await test_client.receive_offer(offer["credential_offer"], did)
