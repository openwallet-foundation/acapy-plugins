from typing import Any, Dict
from acapy_controller.controller import Controller
import pytest

from credo_wrapper import CredoWrapper


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer(credo: CredoWrapper, offer: Dict[str, Any]):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(offer["credential_offer"])


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer_by_ref(
    credo: CredoWrapper, offer_by_ref: Dict[str, Any]
):
    """Test OOB DIDExchange Protocol where offer is passed by reference from the
    credential-offer-by-ref endpoint and then dereferenced."""
    await credo.openid4vci_accept_offer(offer_by_ref["credential_offer"])


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer_sdjwt(credo: CredoWrapper, sdjwt_offer: str):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(sdjwt_offer)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_credential_offer_sdjwt_by_ref(
    credo: CredoWrapper, sdjwt_offer_by_ref: str
):
    """Test OOB DIDExchange Protocol where offer is passed by reference from the
    credential-offer-by-ref endpoint and then dereferenced."""
    await credo.openid4vci_accept_offer(sdjwt_offer_by_ref)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_auth_request(
    controller: Controller, credo: CredoWrapper, offer: Dict[str, Any], request_uri: str
):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(offer["credential_offer"])
    await credo.openid4vp_accept_request(request_uri)
    await controller.event_with_values("oid4vp", state="presentation-valid")


@pytest.mark.interop
@pytest.mark.asyncio
async def test_accept_sdjwt_auth_request(
    controller: Controller,
    credo: CredoWrapper,
    sdjwt_offer: str,
    sdjwt_request_uri: str,
):
    """Test OOB DIDExchange Protocol."""
    await credo.openid4vci_accept_offer(sdjwt_offer)
    await credo.openid4vp_accept_request(sdjwt_request_uri)
    await controller.event_with_values("oid4vp", state="presentation-valid")
