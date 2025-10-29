"""Status Request and response tests"""

from echo_agent.client import EchoClient
from echo_agent.models import ConnectionInfo
import pytest

import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_send_and_receive(echo: EchoClient, connection: ConnectionInfo):
    """Testing the Status Request Message with no queued messages."""
    await echo.send_message(
        connection,
        {
            "@type": "https://didcomm.org/trust_ping/1.0/ping",
            "response_resquested": True,
        },
    )
    response = await echo.get_message(connection)
    assert response["@type"] == ("https://didcomm.org/trust_ping/1.0/ping_response")
