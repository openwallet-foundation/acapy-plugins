from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, Mock

from aries_cloudagent.core.event_bus import EventBus
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.core.protocol_registry import ProtocolRegistry

from .. import setup


class TestInit(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session_inject = {}
        self.context = MagicMock()
        self.profile = InMemoryProfile.test_profile()

    async def test_setup_injects_protocol_registry(self):
        self.context.inject = Mock()
        await setup(self.context)

        self.context.inject.assert_any_call(ProtocolRegistry)

    async def test_setup_injects_plugin_registry(self):
        self.context.inject = Mock()
        await setup(self.context)

        self.context.inject.assert_any_call(PluginRegistry)

    async def test_setup_injects_event_bus(self):
        self.context.inject = Mock()
        await setup(self.context)

        self.context.inject.assert_any_call(EventBus)

    async def test_setup_raises_value_error_when_inject_fails(self):
        self.context.inject = MagicMock().return_value = lambda _: None
        with self.assertRaises(ValueError):
            await setup(self.context)
