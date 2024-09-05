from os import getenv

import pytest_asyncio
from jrpc_client import JsonRpcClient, TCPSocketTransport

from sphereon_wrapper import SphereaonWrapper
from credo_wrapper import CredoWrapper

SPHEREON_HOST = getenv("SPHEREON_HOST", "localhost")
SPHEREON_PORT = int(getenv("SPHEREON_PORT", "3000"))
CREDO_HOST = getenv("CREDO_HOST", "localhost")
CREDO_PORT = int(getenv("CREDO_PORT", "3000"))


@pytest_asyncio.fixture
async def sphereon():
    """Create a wrapper instance and connect to the server."""
    transport = TCPSocketTransport(SPHEREON_HOST, SPHEREON_PORT)
    client = JsonRpcClient(transport)
    wrapper = SphereaonWrapper(transport, client)
    async with wrapper as wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def credo():
    """Create a wrapper instance and connect to the server."""
    transport = TCPSocketTransport(CREDO_HOST, CREDO_PORT)
    client = JsonRpcClient(transport)
    wrapper = CredoWrapper(transport, client)
    async with wrapper as wrapper:
        yield wrapper
