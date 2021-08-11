"""Basic Message Tests"""
import asyncio
import pytest

from aries_staticagent import StaticConnection


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
    assert agent.mock_event_bus.events == []
