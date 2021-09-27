"""Basic Message Tests"""
import asyncio
from acapy_client.models.send_message import SendMessage

import pytest

from aries_staticagent import StaticConnection
from acapy_client import Client
from acapy_client.api.basicmessage import send_basicmessage


@pytest.mark.asyncio
async def test_event_pushed_to_kafka(
    connection: StaticConnection, connection_id: str, consumer
):
    async with consumer("acapy-basicmessage-received") as consumer:
        await connection.send_async(
            {
                "@type": "https://didcomm.org/basicmessage/1.0/message",
                "connection_id": connection_id,
                "content": "Your hovercraft is full of eels.",
            }
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
        print(msg)
