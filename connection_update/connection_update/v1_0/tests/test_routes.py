import asynctest
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.connections.models.conn_record import ConnRecord
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from .. import routes as test_module


class TestRoutes(AsyncTestCase):
    async def setUp(self) -> None:
        self.session_inject = {}
        self.context = AdminRequestContext.test_context(self.session_inject)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": async_mock.CoroutineMock(),
        }
        self.request = async_mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        self.test_conn_id = "connection-id"

    @asynctest.patch.object(ConnRecord, "retrieve_by_id")
    async def test_connections_update_saves_with_alias_from_body(self, mock_retrieve):
        self.request.json = async_mock.CoroutineMock()
        self.request.json.return_value = {
            'alias': 'test-alias'

        }
        self.request.match_info = {"conn_id": self.test_conn_id}

        mock_retrieve.return_value = async_mock.CoroutineMock(
            save=async_mock.CoroutineMock(), alias="", serialize=lambda: {})

        await test_module.connections_update(self.request)

        mock_retrieve.return_value.save.assert_called
        assert mock_retrieve.return_value.alias == 'test-alias'

    async def test_register(self):
        mock_app = async_mock.MagicMock()
        mock_app.add_routes = async_mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called()
