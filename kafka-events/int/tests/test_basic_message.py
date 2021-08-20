"""Basic Message Tests"""
import asyncio
from acapy_backchannel.models.send_message import SendMessage
import pytest
import time

from aries_staticagent import StaticConnection
from acapy_backchannel import Client
from acapy_backchannel.api.basicmessage import post_connections_conn_id_send_message


@pytest.mark.asyncio
async def test_send(connection: StaticConnection, connection_id: str, agent):
    await asyncio.wait_for(
        connection.send_async(
            {
                "@type": "https://didcomm.org/basicmessage/1.0/message",
                "connection_id": connection_id,
                "content": "Your hovercraft is full of eels.",
            }
        ),
        timeout=60,
    )
    time.sleep(4)
    assert agent.received == []


@pytest.mark.asyncio
async def test_send_via_backchannel(backchannel: Client, connection_id: str):
    await post_connections_conn_id_send_message.asyncio(
        client=backchannel.with_timeout(20),
        conn_id=connection_id,
        json_body=SendMessage(content="test"),
    )
