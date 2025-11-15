"""Status Request and response tests"""

from os import getenv
import pytest
from acapy_controller import Controller
from acapy_controller.protocols import (
    didexchange,
)


import logging

LOGGER = logging.getLogger(__name__)

AGENT = getenv("ADMIN_ENDPOINT", "http://agent-host:3004")
BOB = getenv("BOB_ENDPOINT", "http://bob:4001")


@pytest.mark.asyncio
async def test_send_and_receive():
    async with Controller(base_url=AGENT) as agent, Controller(base_url=BOB) as bob:
        conn, _ = await didexchange(agent, bob)

    # """Testing the Status Request Message with no queued messages."""
    # # await echo.send_message(
    # #     connection,
    # #     {
    # #         "@type": "https://didcomm.org/trust_ping/1.0/ping",
    # #         "response_resquested": True,
    # #     },
    # # )
    # # response = await echo.get_message(connection)
    # # assert response["@type"] == ("https://didcomm.org/trust_ping/1.0/ping_response")


@pytest.mark.asyncio
async def test_redis_client(redis_client):
    """Create a credential definition"""

    async with Controller(base_url=AGENT) as agent, Controller(base_url=BOB) as bob:
        await didexchange(agent, bob)

        # Get the list of connections
        response = await agent.get("/connections")
        assert response

        assert response["results"][0]["connection_id"]

        raw_connection_info = await redis_client.keys("ACA-Py:connection_by_verkey::*")

        assert raw_connection_info

        raw_resolver_info = await redis_client.keys(
            "ACA-Py:resolver::PeerDID4Resolver::*"
        )

        assert raw_resolver_info
