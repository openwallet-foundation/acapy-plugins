"""Test setup."""
from unittest import mock

from aiokafka import AIOKafkaProducer
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import EventBus, MockEventBus
import pytest

import kafka_queue as test_module


@pytest.fixture
def event_bus():
    yield MockEventBus()


@pytest.fixture
def context(event_bus):
    context = InjectionContext()
    context.injector.bind_instance(EventBus, event_bus)
    yield context


async def mock_start():
    return


@pytest.mark.asyncio
async def test_setup(context, event_bus):
    mock_producer = mock.MagicMock(spec=AIOKafkaProducer)
    mock_producer.start = mock_start
    with mock.patch.object(
        test_module, "AIOKafkaProducer", mock.MagicMock(return_value=mock_producer)
    ):
        await test_module.setup(context)
        assert event_bus.topic_patterns_to_subscribers
