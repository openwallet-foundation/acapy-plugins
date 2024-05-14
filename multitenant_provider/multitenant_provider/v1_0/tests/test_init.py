from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.core.protocol_registry import ProtocolRegistry
from aries_cloudagent.multitenant.base import BaseMultitenantManager
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from .. import on_startup, setup


class TestInit(AsyncTestCase):
    async def setUp(self) -> None:
        self.session_inject = {}
        self.context = async_mock.MagicMock()
        self.profile = InMemoryProfile.test_profile()

    async def test_setup_injects_protocol_registry(self):
        self.context.inject = async_mock.Mock()
        await setup(self.context)

        self.context.inject.assert_any_call(ProtocolRegistry)

    async def test_setup_injects_event_bus(self):
        self.context.inject = async_mock.Mock()
        await setup(self.context)

        self.context.inject.assert_any_call(EventBus)

    async def test_setup_raises_value_error_when_inject_protocol_registry_fails(self):
        self.context.inject = async_mock.Mock().return_value = lambda _: None
        with self.assertRaises(AssertionError):
            await setup(self.context)

    async def test_setup_raises_value_error_when_second_inject_returns_none(self):
        self.context.inject = async_mock.Mock(side_effect=["test", None])
        with self.assertRaises(ValueError):
            await setup(self.context)

    async def test_on_startup_injects_base_multi_tenant_provider_when_setting_true(
        self,
    ):
        self.profile.context.settings = {"multitenant.enabled": True}
        self.profile.context.injector.bind_instance = async_mock.Mock()
        self.profile.context.injector.bind_provider = async_mock.Mock()
        self.profile.context.inject = async_mock.Mock()
        event = Event(topic="test", payload={})
        await on_startup(self.profile, event)

        self.profile.context.inject.assert_any_call(BaseMultitenantManager)

    async def test_on_startup_raises_error_when_config_missing(self):
        self.profile.context.settings = {}
        event = Event(topic="test", payload={})

        with self.assertRaises(ValueError):
            await on_startup(self.profile, event)

    async def test_on_startup_raises_error_when_config_false(self):
        self.profile.context.settings = {"multitenant.enabled": False}
        event = Event(topic="test", payload={})

        with self.assertRaises(ValueError):
            await on_startup(self.profile, event)
