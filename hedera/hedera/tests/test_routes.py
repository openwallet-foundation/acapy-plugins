import json
from typing import cast
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import KeyTypes
from aiohttp import web
from hedera import routes as test_module
import pytest


class TestRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.wallet = create_autospec(BaseWallet)
        self.session_inject = {BaseWallet: self.wallet}
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "admin_api_key",
                "admin.admin_insecure_mode": False,
                "plugin_config": {
                    "hedera": {
                        "network": "testnet",
                        "operator_id": "0.0.1",
                        "operator_key": "31ACDD47830239324BA37D493F959A1585774DBC04DA0679C162B95151F6593C",
                    }
                },
            }
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": MagicMock(),
        }

        self.request = MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "admin_api_key"},
            json=AsyncMock(return_value={}),
        )

    async def test_register_did_throws_on_missing_wallet(self):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"key_type": "Ed25519"}

        self.session_inject[BaseWallet] = None

        with pytest.raises(
            web.HTTPInternalServerError, match="Failed to inject wallet instance"
        ):
            await test_module.hedera_register_did(self.request)

    async def test_register_did_throws_on_missing_key_types(self):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"key_type": "Ed25519"}

        self.session_inject[KeyTypes] = None

        with pytest.raises(
            web.HTTPInternalServerError, match="Failed to inject supported key types enum"
        ):
            await test_module.hedera_register_did(self.request)

    async def test_register_did_unsupported_key_type(self):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"key_type": "unsupported_key_type"}

        with pytest.raises(
            web.HTTPForbidden, match="Unsupported key type unsupported_key_type"
        ):
            await test_module.hedera_register_did(self.request)

    @patch("hedera.routes.HederaDIDRegistrar")
    async def test_register_did(self, mock_did_registrar):
        mock_did_info = {
            "did": "did:hedera:testnet:zEBxZtv3ttiDsySAYa6eNxorEYSnUk7WsKJBUfUjFQiLL_0.0.5244981",
            "verkey": "DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX",
            "key_type": "Ed25519",
        }
        mock_did_registrar.return_value.register = AsyncMock(return_value=mock_did_info)

        self.request.json = AsyncMock(
            return_value={"key_type": mock_did_info["key_type"]}
        )

        result = await test_module.hedera_register_did(self.request)
        body = cast(bytes, result.body)

        assert result.status == 200
        assert json.loads(body) == mock_did_info

    async def test_post_process_routes(self):
        mock_app = MagicMock(_state={"swagger_dict": {}})

        test_module.post_process_routes(mock_app)

        app_state = mock_app._state
        tags = app_state["swagger_dict"]["tags"]

        assert tags

        hedera_tags = [i for i in tags if i["name"] == "hedera"][0]

        assert hedera_tags
        assert hedera_tags.get("name") == "hedera"
        assert hedera_tags.get("description") == "Hedera plugin API"
        assert "externalDocs" in hedera_tags
