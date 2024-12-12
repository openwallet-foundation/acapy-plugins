from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.event_bus import MockEventBus
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.storage.error import StorageNotFoundError
from aiohttp import web

from .. import routes as test_module


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
        self.request_dict = {"context": self.context}
        self.request = MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "admin_api_key"},
        )

    async def test_register_events_subscribes_to_event_bus(self):
        mock_event_bus = MockEventBus()
        mock_event_bus.subscribe = MagicMock()
        test_module.register_events(mock_event_bus)
        self.assertEqual(mock_event_bus.subscribe.called, True)

    @patch.object(
        ConnRecord, "retrieve_by_id", side_effect=[StorageNotFoundError("test")]
    )
    async def test_set_connection_device_info_no_connection(self, mock_conn):
        self.request.match_info = {"conn_id": "test-conn-id"}
        with self.assertRaises(web.HTTPNotFound):
            await test_module.set_connection_device_info(self.request)
            assert mock_conn.called

    @patch.object(ConnRecord, "retrieve_by_id", return_value=None)
    @patch.object(test_module, "save_device_token")
    async def test_set_connection_device_info_with_connection(
        self, mock_save_info, mock_conn
    ):
        self.request.match_info = {"conn_id": "test-conn-id"}
        await test_module.set_connection_device_info(self.request)
        assert mock_conn.called
        assert mock_save_info.called
