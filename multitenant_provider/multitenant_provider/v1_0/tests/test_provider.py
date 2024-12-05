from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

from acapy_agent.config.base import InjectionError
from acapy_agent.utils.classloader import ClassLoader, ClassNotFoundError
from acapy_agent.utils.testing import create_test_profile

from multitenant_provider.v1_0.config import MultitenantProviderConfig

from ..provider import CustomMultitenantManagerProvider


class TestProvider(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile()
        self.profile.inject = Mock()
        self.profile.inject.return_value = MultitenantProviderConfig.default()

    @patch.object(ClassLoader, "load_class")
    async def test_provide_loads_manager(self, mock_class_loader):
        mock_class_loader.return_value = lambda _: {"test-class-name": "manager"}
        provider = CustomMultitenantManagerProvider(self.profile)
        result = provider.provide({}, {})
        assert result["test-class-name"] == "manager"

    @patch.object(ClassLoader, "load_class")
    async def test_provide_raises_error_when_loading_class_fails(self, mock_class_loader):
        mock_class_loader.return_value = lambda _: (_ for _ in ()).throw(
            ClassNotFoundError("test-message")
        )
        provider = CustomMultitenantManagerProvider(self.profile)
        with self.assertRaises(InjectionError):
            provider.provide({}, {})
