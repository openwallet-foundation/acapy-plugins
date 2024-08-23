import pytest

from credo_wrapper import CredoWrapper


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer(credo: CredoWrapper, offer: str):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(offer)
