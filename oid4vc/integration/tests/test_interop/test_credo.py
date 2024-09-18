from acapy_controller.controller import Controller
import pytest

from credo_wrapper import CredoWrapper


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer(credo: CredoWrapper, offer: str):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(offer)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer_sdjwt(credo: CredoWrapper, sdjwt_offer: str):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(sdjwt_offer)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_auth_request(controller: Controller, credo: CredoWrapper, offer: str, request_uri: str):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(offer)
    await credo.openid4vp_accept_request(request_uri)
    await controller.event_with_values("oid4vp", state="presentation-valid")
