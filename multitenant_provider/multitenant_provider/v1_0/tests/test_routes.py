import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from aiohttp import web
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.multitenant.base import BaseMultitenantManager
from aries_cloudagent.wallet.models.wallet_record import WalletRecord

from .. import routes as test_module
from ..config import MultitenantProviderConfig


class MockResource:
    def __init__(self, path: str) -> None:
        self.canonical = path


class MockRoute:
    def __init__(self, path: str) -> None:
        self.resource = MockResource(path)

    method = "POST"
    handler = "handler"
    _handler = None


class MockErrors:
    class Error:
        on_unneeded_wallet_key = True

    errors = Error


class MockWalletRecordRequiresExternalKey:
    requires_external_key = False


class TestRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session_inject = {}
        self.profile = InMemoryProfile.test_profile()
        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        self.profile.session = mock_session
        self.context = AdminRequestContext.test_context(
            self.session_inject, profile=self.profile
        )
        self.request_dict = {
            "context": self.context,
        }
        self.request = MagicMock(
            app={},
            match_info={"wallet_id": "test-wallet-id"},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            context=self.context,
        )

    @patch.object(WalletRecord, "retrieve_by_id")
    async def test_plugin_wallet_create_token_returns_token_with_wallet_key(
        self, mock_retrieve
    ):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"wallet_key": "test-wallet-key"}
        mock_manager = MagicMock(BaseMultitenantManager)
        mock_manager.create_auth_token.return_value = "token"
        self.context.profile.inject = Mock(
            side_effect=[
                MultitenantProviderConfig().default(),
                mock_manager,
            ]
        )
        mock_retrieve.return_value = AsyncMock(requires_external_key=lambda: True)
        result = await test_module.plugin_wallet_create_token(self.request)
        assert result is not None
        assert json.loads(result.body)["token"] == "token"

    async def test_plugin_wallet_create_token_raises_unauthorized_with_no_wallet_key(
        self,
    ):
        self.request.json = AsyncMock()
        self.request.body_exists = False
        with self.assertRaises(web.HTTPUnauthorized):
            await test_module.plugin_wallet_create_token(self.request)

        self.request.body_exists = True
        self.request.json.return_value = {"wallet_key": ""}
        with self.assertRaises(web.HTTPUnauthorized):
            await test_module.plugin_wallet_create_token(self.request)

    @patch.object(
        WalletRecord, "retrieve_by_id", return_value=MockWalletRecordRequiresExternalKey
    )
    async def test_plugin_wallet_create_token_with_requires_external_token_and_token_raise_bad_request(
        self, _
    ):
        self.request.context.profile.inject = MagicMock(
            side_effect=[MockErrors, "not-needed"]
        )
        self.request.json = AsyncMock()
        self.request.body_exists = True
        self.request.json.return_value = {"wallet_key": "test-wallet-key"}
        with self.assertRaises(web.HTTPBadRequest):
            await test_module.plugin_wallet_create_token(self.request)

    async def test_register_replaces_endpoints_without_adding_routes(self):
        mock_app = MagicMock()
        mock_app.router.routes = MagicMock()
        wallet_route = MockRoute("/multitenancy/wallet")
        wallet_token_route = MockRoute("/multitenancy/wallet/{wallet_id}/token")
        mock_app.router.routes.return_value = [
            wallet_route,
            wallet_token_route,
        ]
        mock_app.add_routes = MagicMock()

        await test_module.register(mock_app)
        assert wallet_route._handler is not None
        assert wallet_token_route._handler is not None

    # Should be impossible
    async def test_register_adds_expected_endpoints_if_plugin_loaded_first(self):
        mock_app = MagicMock()
        mock_app.add_routes = MagicMock()
        await test_module.register(mock_app)
        assert mock_app.add_routes.call_count == 2

    async def test_post_process_routes(self):
        mock_app = MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
