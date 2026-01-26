from os import getenv

from acapy_controller.controller import Controller
from acapy_controller.protocols import indy_anoncred_onboard
from jrpc_client import JsonRpcClient, TCPSocketTransport
import pytest_asyncio

from credo_wrapper import CredoWrapper


ISSUER_ADMIN_ENDPOINT = getenv("ISSUER_ADMIN_ENDPOINT", "http://localhost:3001")
CREDO_HOST = getenv("CREDO_HOST", "localhost")
CREDO_PORT = int(getenv("CREDO_PORT", "3000"))


@pytest_asyncio.fixture
async def controller():
    """Connect to Issuer."""
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with controller:
        yield controller


@pytest_asyncio.fixture
async def sov_did(controller: Controller):
    did_info = await indy_anoncred_onboard(controller)
    yield did_info.did


@pytest_asyncio.fixture
async def indy_did(controller: Controller, sov_did: str):
    did_indy_result = await controller.post(
        "/did/indy/from-nym",
        json={
            "ldp_vc": True,
            "didcomm": True,
        },
    )
    yield did_indy_result["did"]


@pytest_asyncio.fixture
async def credo():
    """Create a wrapper instance and connect to the server."""
    transport = TCPSocketTransport(CREDO_HOST, CREDO_PORT)
    client = JsonRpcClient(transport)
    wrapper = CredoWrapper(transport, client)
    async with wrapper as wrapper:
        yield wrapper
