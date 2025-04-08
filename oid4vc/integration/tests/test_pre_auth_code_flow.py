"""Quick test script."""

import pytest

from oid4vci_client.client import OpenID4VCIClient


@pytest.mark.asyncio
async def test_pre_auth_code_flow_ed25519(test_client: OpenID4VCIClient, offer: str):
    """Connect to AFJ."""
    did = test_client.generate_did("ed25519")
    response = await test_client.receive_offer(offer, did)


@pytest.mark.asyncio
async def test_pre_auth_code_flow_secp256k1(test_client: OpenID4VCIClient, offer: str):
    """Connect to AFJ."""
    did = test_client.generate_did("secp256k1")
    response = await test_client.receive_offer(offer, did)
