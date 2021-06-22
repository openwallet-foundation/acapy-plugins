"""Test AIO Producer."""

from aries_cloudagent.core.event_bus import Event, EventBus
from pytest_mock import MockerFixture
import pytest
from kafka_events.aio_producer import AIOProducer

event_bus = EventBus()


@pytest.mark.asyncio
async def test_produce_kafka_msg(mocker: MockerFixture):
    async def aux_function(*args, **kwargs):
        pass

    producer = AIOProducer()
    aio_kafka = mocker.patch("kafka_events.aio_producer.AIOKafkaProducer").return_value
    aio_kafka.start.side_effect = aux_function
    aio_kafka.stop.side_effect = aux_function
    aio_kafka.send_and_wait.side_effect = aux_function

    await producer.produce("test::topic", {"payload": "test"})
    assert aio_kafka.start.called
    assert aio_kafka.stop.called
    assert aio_kafka.send_and_wait.called


@pytest.mark.asyncio
async def test_exception_raised_to_produce_kafka_msg(mocker: MockerFixture):
    async def aux_function(*args, **kwargs):
        pass

    producer = AIOProducer()
    aio_kafka = mocker.patch("kafka_events.aio_producer.AIOKafkaProducer").return_value
    logger = mocker.patch("kafka_events.aio_producer.LOGGER")
    aio_kafka.start.side_effect = aux_function
    aio_kafka.stop.side_effect = aux_function

    await producer.produce("test::topic", {"payload": "test"})
    assert aio_kafka.start.called
    assert aio_kafka.stop.called
    assert logger.error.called
