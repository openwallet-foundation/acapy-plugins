"""Testing basic kafka stuff."""

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
import pytest


@pytest.mark.asyncio
async def test_round_trip():
    """Test that we can get to and from Kafka."""
    producer = AIOKafkaProducer(bootstrap_servers="kafka")
    consumer = AIOKafkaConsumer(
        "test-topic", bootstrap_servers="kafka", group_id="test"
    )

    async with consumer:
        await producer.send_and_wait(b"test-topic", b"test-payload")
        async for msg in consumer:
            assert msg
