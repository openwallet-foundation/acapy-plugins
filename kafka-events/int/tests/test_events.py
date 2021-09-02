"""Basic Message Tests"""
import asyncio
from typing import Callable

from aiokafka.consumer.consumer import AIOKafkaConsumer
import pytest

from aries_staticagent import StaticConnection


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
        msg = await asyncio.wait_for(consumer.getone(), 1)
        assert msg
