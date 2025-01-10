import json
from typing import cast
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, Mock, create_autospec, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet, KeyInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from aiohttp import web
from hedera_did import routes as test_module
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
                        "hedera_did": {
                            "network": "<CHANGE_ME>",
                            "operator_id": "<CHANGE_ME>",
                            "operator_key_der": "<CHANGE_ME>"
                        }
                    }
                }
            )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": MagicMock()
        }

        self.request = MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "admin_api_key"},
            json = AsyncMock(return_value={})
        )
        self.test_conn_id = "connection-id"

    async def test_missing_wallet(self):
        self.request.json = AsyncMock()
        self.request.json.return_value = { "key_type": "Ed25519" }

        self.session_inject[BaseWallet] = None

        with pytest.raises(web.HTTPForbidden, match="No wallet available"):
          await test_module.hedera_register_did(self.request)


    async def test_hedera_register_did_unsupported_key_type(self):
        self.request.json = AsyncMock()
        self.request.json.return_value = { "key_type": "unsupported_key_type" }

        with pytest.raises(web.HTTPForbidden, match="Unsupported key type unsupported_key_type"):
            await test_module.hedera_register_did(self.request)


    @patch("hedera_did.routes.HederaDid")
    async def test_hedera_register_did(self, mock_hedera_did):
        key_type = "Ed25519"
        ver_key = "DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX"
        did = "did:hedera:testnet:zEBxZtv3ttiDsySAYa6eNxorEYSnUk7WsKJBUfUjFQiLL_0.0.5244981"

        self.request.json = AsyncMock(
                return_value = {
                    "key_type": key_type
                    }
                )

        self.wallet._session = MagicMock(
                handle=AsyncMock(
                    fetch_key=AsyncMock(
                        return_value=Mock(
                            key=Mock(
                                get_secret_bytes=Mock(
                                    return_value=b"\xbcAQ\xb8\x91NZP\xb4\x99\xf6f\xb7\xff\xca\x7f\xffO\x9aC\xdb\xbf\xea\xed2\x83\xa0\xf2\xc1\xca\t]"
                                    )
                                )
                            )
                        ),
                    insert=AsyncMock(
                        return_value=None
                        )
                    )
                )

        self.wallet.create_key.return_value = KeyInfo(ver_key, {}, ED25519)

        mock_hedera_did.return_value.register = AsyncMock(return_value = {})
        mock_hedera_did.return_value.identifier = did

        result = await test_module.hedera_register_did(self.request)
        body = cast(bytes, result.body)

        assert result.status == 200
        assert json.loads(body) == {
                "did": did,
                "verkey": ver_key,
                "key_type": ED25519.key_type
                }


    async def test_post_process_routes(self):
        mock_app = MagicMock(_state={"swagger_dict": {}})

        test_module.post_process_routes(mock_app)

        app_state = mock_app._state
        tags = app_state["swagger_dict"]["tags"]

        assert tags

        hedera_tags = [i
                       for i in tags
                       if i["name"] == "Hedera"
                       ][0]

        assert hedera_tags
        assert hedera_tags.get("name") == "Hedera"
        assert hedera_tags.get("description") == "Hedera plugin API"
        assert "externalDocs" in hedera_tags
