"""Test AIO Producer."""
from unittest.mock import MagicMock

from aries_cloudagent.core.event_bus import Event, EventBus
from pytest_mock import MockerFixture
import pytest
from kafka_events.aio_consumer import AIOConsumer

event_bus = EventBus()


@pytest.mark.asyncio
async def test_consume_kafka_msg(mocker: MockerFixture):
    async def aux_function(*args, **kwargs):
        pass

    context = MagicMock()
    consumer = AIOConsumer(context, pattern="acapy-inbound-.*")
    aio_kafka = mocker.patch("kafka_events.aio_consumer.AIOKafkaConsumer").return_value
    aio_kafka.start.side_effect = aux_function

    await consumer.start()
    assert aio_kafka.start.called


@pytest.mark.asyncio
async def test_raised_exception_in_consume_kafka_msg(mocker: MockerFixture):
    async def aux_function(*args, **kwargs):
        pass

    def aux_suscribe(*args, **kwargs):
        raise Exception("test")

    context = MagicMock()
    consumer = AIOConsumer(context, pattern="acapy-inbound-.*")
    aio_kafka = mocker.patch("kafka_events.aio_consumer.AIOKafkaConsumer").return_value
    logger = mocker.patch("kafka_events.aio_consumer.LOGGER")
    aio_kafka.start.side_effect = aux_function
    aio_kafka.subscribe.side_effect = aux_suscribe

    await consumer.start()
    assert aio_kafka.start.called
    assert logger.error.called
