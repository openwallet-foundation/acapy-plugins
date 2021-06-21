"""Test event handler."""

# pylint: disable=redefined-outer-name
from unittest.mock import MagicMock

from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.profile import Profile
from pytest_mock import MockerFixture
import pytest
from kafka_events import setup as event_setup
from kafka_events import teardown as event_teardown

event_bus = EventBus()


@pytest.mark.asyncio
async def setup_module(profile: Profile):
    """ setup for execution of the given module."""
    context = MagicMock()
    context.settings = {}
    context.inject.return_value = event_bus
    await event_setup(context)


@pytest.mark.asyncio
async def test_setup_and_receive_event_to_be_produced_to_kafka(mocker: MockerFixture):
    """Test event handler setup and event receive."""

    async def aux_produce(*args):
        pass

    await setup_module(Profile)
    mocker.patch("kafka_events.AIOProducer")
    mocker.patch("kafka_events.AIOConsumer")
    profile = MagicMock()
    kafka_productor = profile.context.inject.return_value.produce
    kafka_productor.side_effect = aux_produce
    await event_bus.notify(profile, Event("acapy::outbound::test"))
    assert kafka_productor.called


@pytest.mark.skip(msg="Pending")
@pytest.mark.asyncio
async def test_teardown(mocker: MockerFixture):
    pass
