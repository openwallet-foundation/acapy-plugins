import asynctest
from aries_cloudagent.core.event_bus import Event
from aries_cloudagent.core.in_memory import InMemoryProfile
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock
from aries_cloudagent.multitenant.admin.routes import ACAPY_LIFECYCLE_CONFIG_FLAG_MAP, ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP 
from .. import basic_message_event_handler, setup
from ..models import BasicMessageRecord


class TestInit(AsyncTestCase):
    async def setUp(self) -> None:
        self.session_inject = {}
        self.context = async_mock.MagicMock()
        self.profile = InMemoryProfile.test_profile()

    async def test_setup_injects_and_finishes_by_subscribing_to_event_bus(self):
        self.context.inject = async_mock.Mock()
        await setup(self.context)

        last_call_as_string = self.context.mock_calls[-1].__str__()
        assert (
            "subscribe(re.compile('^acapy::basicmessage::received$')"
            in last_call_as_string
        )
        assert "basic_message_event_handler" in last_call_as_string
        assert self.context.inject.call_count == 2

    async def test_setup_injects_subwallet_config(self):
        self.context.inject = async_mock.Mock()
        await setup(self.context)
        assert "basicmessage-storage" in ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP
       

    async def test_setup_throws_error_when_injecting_protocol_registry_fails(self):
        self.context.inject = async_mock.Mock(side_effect=[None, None])
        with self.assertRaises(AssertionError):
            await setup(self.context)

    async def test_setup_throws_error_when_injecting_event_bus_fails(self):
        self.context.inject = async_mock.Mock(side_effect=["test", None])
        with self.assertRaises(ValueError):
            await setup(self.context)

    @asynctest.patch.object(BasicMessageRecord, "save")
    async def test_basic_message_event_handler_saves_record(self, mock_save):
        event = Event(topic="test", payload={})
        await basic_message_event_handler(self.profile, event)

        assert mock_save.called


