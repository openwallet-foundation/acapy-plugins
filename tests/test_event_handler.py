"""Test event handler."""

# pylint: disable=redefined-outer-name

from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.core.profile import Profile
from pytest_mock import MockerFixture
import pytest

from kafka_events import setup as event_setup
from kafka_events import teardown as event_teardown


@pytest.fixture
def event_bus():
    """Event bus fixture."""
    yield EventBus()


@pytest.fixture
def profile(event_bus):
    """Profile fixture."""
    yield InMemoryProfile.test_profile(bind={EventBus: event_bus})

@pytest.mark.asyncio
async def setup_module(profile: Profile):
    """ setup for execution of the given module."""
    await event_setup(profile.context)

@pytest.mark.asyncio
async def teardown_module():
    """ teardown previously setup from setup_module
    method.
    """
    await event_teardown(profile.context)

@pytest.mark.asyncio
async def test_setup_and_receive_event(
    profile: Profile, event_bus: EventBus, mocker: MockerFixture
):
    """Test event handler setup and event receive."""
    mock_handle_event = mocker.patch("kafka-events.handle_event")
    await event_bus.notify(profile, Event("acapy::record::test"))
    mock_handle_event.assert_called_once()

@pytest.mark.asyncio
async def test_kafka_produce_event(
    profile: Profile, event_bus: EventBus, mocker: MockerFixture
):
    """Test event handler setup and event receive."""
    mock_handle_event = mocker.patch("kafka-events.handle_event")
    await event_bus.notify(profile, Event("acapy::record::test"))
    mock_handle_event.assert_called_once()
    # check zookeeper for produced event