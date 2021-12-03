"""Basic Message Tests"""
import asyncio
from acapy_client.models.send_message import SendMessage
from echo_agent.client import EchoClient
from echo_agent.models import ConnectionInfo

import pytest

from acapy_client import Client
from acapy_client.api.basicmessage import send_basicmessage


@pytest.mark.asyncio
async def test_event_pushed_to_kafka(
    connection: ConnectionInfo, echo: EchoClient, consumer
):
    async with consumer("acapy-basicmessage-received") as consumer:
        await echo.send_message(
            connection,
            {
                "@type": "https://didcomm.org/basicmessage/1.0/message",
                "content": "Your hovercraft is full of eels.",
            },
        )
        msg = await asyncio.wait_for(consumer.getone(), 5)
        assert msg


@pytest.mark.asyncio
async def test_outbound_queue(backchannel: Client, connection_id: str, consumer):
    async with consumer("acapy-outbound-message") as consumer:
        await send_basicmessage.asyncio(
            client=backchannel,
            conn_id=connection_id,
            json_body=SendMessage(content="test"),
        )
        msg = await asyncio.wait_for(consumer.getone(), 5)
        assert msg


@pytest.mark.asyncio
async def test_deliverer(
    backchannel: Client,
    connection_id: str,
    echo: EchoClient,
    connection: ConnectionInfo,
):
    await send_basicmessage.asyncio(
        client=backchannel,
        conn_id=connection_id,
        json_body=SendMessage(content="test"),
    )
    await asyncio.sleep(1)
    message = await echo.get_message(connection)
    assert message["content"] == "test"


@pytest.mark.asyncio
async def test_deliverer_retry_on_failure(
    backchannel: Client,
    connection_id: str,
    echo: EchoClient,
    connection: ConnectionInfo,
):
    print(ConnectionInfo)
    assert False
