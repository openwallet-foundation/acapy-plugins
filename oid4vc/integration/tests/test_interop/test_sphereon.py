import pytest

from sphereon_wrapper import SphereaonWrapper


@pytest.mark.interop
@pytest.mark.asyncio
async def test_api(sphereon: SphereaonWrapper):
    """Test that we can hit the sphereon rpc api."""

    result = await sphereon.test()
    assert result
    assert "test" in result
    assert result["test"] == "success"


@pytest.mark.interop
@pytest.mark.asyncio
async def test_sphereon_pre_auth(sphereon: SphereaonWrapper, offer: str):
    """Test receive offer for pre auth code flow."""
    await sphereon.accept_credential_offer(offer)
