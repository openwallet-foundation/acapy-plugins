import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.protocols.basicmessage.v1_0 import routes as base_module

from basicmessage_storage.v1_0.models import BasicMessageRecord

from .. import routes as test_module
from ..routes import all_messages_list, plugin_connections_send_message
from .test_init import MockConfig


class TestRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session_inject = {}
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "admin_api_key",
                "admin.admin_insecure_mode": False,
            }
        )
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": AsyncMock(),
        }
        self.request = MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "admin_api_key"},
        )
        self.test_conn_id = "connection-id"

    @patch.object(base_module, "ConnRecord", autospec=True)
    @patch.object(test_module, "BasicMessageRecord", autospec=True)
    async def test_plugin_connections_send_message_saves_record(
        self, mock_basic_message_rec_class, _
    ):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"content": "content"}
        self.request.match_info = {"conn_id": self.test_conn_id}
        mock_basic_message_rec = MagicMock(save=AsyncMock())
        mock_basic_message_rec_class.deserialize.return_value = mock_basic_message_rec
        with patch.object(test_module, "get_config") as mock_config:
            mock_config.return_value = MockConfig(wallet_enabled=True)

            res = await plugin_connections_send_message(self.request)

            mock_basic_message_rec.save.assert_called()
        assert res is not None

    @patch.object(base_module, "ConnRecord", autospec=True)
    @patch.object(test_module, "BasicMessageRecord", autospec=True)
    async def test_plugin_connections_send_message_raises_exception_when_save_fails(
        self, mock_basic_message_rec_class, _
    ):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"content": "content"}
        self.request.match_info = {"conn_id": self.test_conn_id}

        # Mock an exception during save
        mock_basic_message_rec = MagicMock(
            save=lambda: (_ for _ in ()).throw(Exception("test"))
        )
        mock_basic_message_rec_class.deserialize.return_value = mock_basic_message_rec
        with patch.object(test_module, "get_config") as mock_config:
            mock_config.return_value = MockConfig(wallet_enabled=True)

            with self.assertRaises(Exception):
                await plugin_connections_send_message(self.request)

    @patch.object(base_module, "ConnRecord", autospec=True)
    @patch.object(test_module, "BasicMessageRecord", autospec=True)
    async def test_all_messages_list_succeeds_and_sorts(
        self, mock_basic_message_rec_class, _
    ):
        mock_basic_message_rec_class.query = AsyncMock()
        mock_basic_message_rec_class.query.return_value = [
            BasicMessageRecord(record_id="2", created_at="2023-10-13T21:49:14Z"),
            BasicMessageRecord(record_id="1", created_at="2023-10-13T20:49:14Z"),
            BasicMessageRecord(record_id="0", created_at="2023-10-13T22:49:14Z"),
        ]
        response = await all_messages_list(self.request)
        results = json.loads(response.body)["results"]

        mock_basic_message_rec_class.query.assert_called()
        assert results[0]["created_at"] == "2023-10-13T22:49:14Z"
        assert results[2]["created_at"] == "2023-10-13T20:49:14Z"

    async def test_register(self):
        mock_app = MagicMock()
        mock_app.add_routes = MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called()

    async def test_post_process_routes(self):
        mock_app = MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]

    @patch.object(BasicMessageRecord, "save")
    @patch.object(base_module, "ConnRecord", autospec=True)
    @patch.object(test_module, "BasicMessageRecord", autospec=True)
    async def test_basic_message_send_does_not_save_if_disabled(
        self, mock_basic_message_rec_class, _, mock_save
    ):
        self.request.json = AsyncMock()
        self.request.json.return_value = {"content": "content"}
        self.request.match_info = {"conn_id": self.test_conn_id}

        mock_basic_message_rec = MagicMock(save=AsyncMock())
        mock_basic_message_rec_class.deserialize.return_value = mock_basic_message_rec

        with patch.object(test_module, "get_config") as mock_config:
            mock_config.return_value = Mock(wallet_enabled=True)
            await plugin_connections_send_message(self.request)
            assert not mock_basic_message_rec.save.assert_called()
