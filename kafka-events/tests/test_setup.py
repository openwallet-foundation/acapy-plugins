"""Test setup."""
import re
from unittest import mock

from aiokafka import AIOKafkaProducer
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.core.event_bus import Event, EventBus, EventMetadata, EventWithMetadata, MockEventBus
import pytest

import kafka_queue as test_module


@pytest.fixture
def event_bus():
    yield MockEventBus()


@pytest.fixture
def producer():
    yield mock.MagicMock(spec=AIOKafkaProducer)


@pytest.fixture
def profile(event_bus, producer):
    yield InMemoryProfile.test_profile(
        {"plugin_config": {"kafka_queue": test_module.DEFAULT_CONFIG}},
        {
            EventBus: event_bus,
            AIOKafkaProducer: producer
        }
    )


@pytest.fixture
def context(profile: Profile):
    yield profile.context


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


@pytest.mark.asyncio
async def test_handle_event(profile, producer: mock.MagicMock):
    topic = "acapy::basicmessage::received"
    pattern = re.compile(topic)
    match = pattern.match(topic)
    assert match
    event = EventWithMetadata(
        topic, {}, EventMetadata(pattern, match)
    )
    await test_module.handle_event(profile, event)
    producer.send_and_wait.assert_called_once()
