"""Testing basic kafka stuff."""

from aiokafka.structs import ConsumerRecord
import pytest


@pytest.mark.asyncio
async def test_round_trip(consumer, producer):
    """Test that we can get to and from Kafka."""
    async with consumer("test-topic") as consumer:
        await producer.send_and_wait("test-topic", b"test-payload")
        async for msg in consumer:
            assert isinstance(msg, ConsumerRecord)
            assert msg.value == b"test-payload"
            break
