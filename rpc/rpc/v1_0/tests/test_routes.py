import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.storage.record import StorageRecord
from aiohttp import web

import rpc.v1_0.routes as test_module
from rpc.v1_0.models import DRPCRecord, DRPCRecordSchema

test_rpc_request = {
    "jsonrpc": "2.0",
    "method": "test.method",
    "id": "1",
    "params": {"one": "1"},
}

test_rpc_response = {"jsonrpc": "2.0", "result": 3, "id": "1"}

test_rpc_error = {
    "jsonrpc": "2.0",
    "error": {"code": -32601, "message": "Method not found"},
    "id": "1",
}

test_tags = {
    "connection_id": "test-connection-id",
    "thread_id": "test-thread-id",
}


class MockConnRecord:
    def __init__(self, connection_id, is_ready):
        self.connection_id = connection_id
        self.is_ready = is_ready


class TestDRPCRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session_inject = {}

        self.storage = MagicMock()
        self.session_inject[test_module.BaseStorage] = self.storage
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
            __getitem__=lambda _, key: self.request_dict[key],
            headers={"x-api-key": "admin_api_key"},
        )

    async def test_get_empty_drpc_record_list(self):
        self.storage.find_all_records = AsyncMock(return_value=[])

        with patch.object(test_module.web, "json_response") as mock_response:
            await test_module.drpc_get_records(self.request)
            mock_response.assert_called_once_with({"results": []})

    async def test_get_drpc_record_list(self):
        self.storage.find_all_records = AsyncMock(
            return_value=[
                StorageRecord(
                    DRPCRecord.RECORD_TYPE,
                    json.dumps(
                        {
                            "state": "request-sent",
                            "request": test_rpc_request,
                        }
                    ),
                    test_tags,
                    "test-record-id",
                )
            ]
        )

        with patch.object(test_module.web, "json_response") as mock_response:
            await test_module.drpc_get_records(self.request)
            mock_response.assert_called_once_with(
                {
                    "results": [
                        {
                            "id": "test-record-id",
                            "tags": test_tags,
                            "request": test_rpc_request,
                            "state": "request-sent",
                        }
                    ]
                }
            )

    async def test_get_drpc_record_list_by_state(self):
        self.storage.find_all_records = AsyncMock(
            return_value=[
                StorageRecord(
                    DRPCRecord.RECORD_TYPE,
                    json.dumps(
                        {
                            "state": "request-sent",
                            "request": test_rpc_request,
                        }
                    ),
                    test_tags,
                    "test-record-id",
                ),
                StorageRecord(
                    DRPCRecord.RECORD_TYPE,
                    json.dumps(
                        {
                            "state": "completed",
                            "request": test_rpc_request,
                        }
                    ),
                    {
                        "connection_id": "test-connection-id-2",
                        "thread_id": "test-thread-id-2",
                    },
                    "test-record-id-2",
                ),
            ]
        )

        with patch.object(test_module.web, "json_response") as mock_response:
            self.request.query = {
                "connection_id": "test-connection-id",
                "thread_id": "test-thread-id",
                "state": "request-sent",
            }
            await test_module.drpc_get_records(self.request)
            mock_response.assert_called_once_with(
                {
                    "results": [
                        {
                            "id": "test-record-id",
                            "tags": test_tags,
                            "request": test_rpc_request,
                            "state": "request-sent",
                        }
                    ]
                }
            )

    async def test_get_drpc_record_by_id(self):
        self.storage.get_record = AsyncMock(
            return_value=StorageRecord(
                DRPCRecord.RECORD_TYPE,
                json.dumps(
                    {
                        "state": "request-sent",
                        "request": test_rpc_request,
                    }
                ),
                test_tags,
                "test-record-id",
            )
        )

        with patch.object(test_module.web, "json_response") as mock_response:
            self.request.match_info = {"record_id": "test-record-id"}
            await test_module.drpc_get_record(self.request)
            mock_response.assert_called_once_with(
                {
                    "id": "test-record-id",
                    "tags": test_tags,
                    "request": test_rpc_request,
                    "state": "request-sent",
                }
            )

    @patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        side_effect=StorageNotFoundError(),
    )
    async def test_http_not_found_thrown_on_connection_not_found_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = AsyncMock(
            return_value={
                "request": test_rpc_request,
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.add_record = AsyncMock()
        self.storage.update_record = AsyncMock()

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_request(self.request)

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_response(self.request)

    @patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    async def test_http_internal_server_error_thrown_on_add_storage_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = AsyncMock(return_value={"request": test_rpc_request})

        self.storage.add_record = AsyncMock(side_effect=StorageError())

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_request(self.request)

    @patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @patch.object(
        test_module.DRPCRecord,
        "retrieve_by_connection_and_thread",
        return_value=DRPCRecordSchema().load(
            {"state": "request-received", "request": test_rpc_request}
        ),
    )
    async def test_http_internal_server_error_thrown_on_update_storage_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = AsyncMock(
            return_value={
                "request": test_rpc_request,
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.add_record = AsyncMock()
        self.storage.update_record = AsyncMock(side_effect=StorageError())

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_request(self.request)

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_response(self.request)

    @patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @patch.object(
        test_module.DRPCRecord,
        "retrieve_by_connection_and_thread",
        side_effect=StorageNotFoundError(),
    )
    async def test_http_not_found_thrown_on_drpc_record_not_found_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = AsyncMock(
            return_value={
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.update_record = AsyncMock()

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_response(self.request)

    @patch.object(
        test_module.DRPCRecord,
        "from_storage",
        side_effect=BaseModelError(),
    )
    async def test_http_internal_server_error_thrown_on_drpc_get_records(self, *_):
        self.storage.find_all_records = AsyncMock(
            return_value=[
                StorageRecord(
                    DRPCRecord.RECORD_TYPE,
                    json.dumps(
                        {
                            "state": "request-sent",
                            "request": test_rpc_request,
                        }
                    ),
                    test_tags,
                    "test-record-id",
                )
            ]
        )

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_get_records(self.request)

    @patch.object(
        test_module.DRPCRecord,
        "from_storage",
        side_effect=BaseModelError(),
    )
    async def test_http_not_found_thrown_on_drpc_get_record(self, *_):
        self.request.match_info = {"record_id": "test-record-id"}

        self.storage.get_record = AsyncMock(
            return_value=StorageRecord(
                DRPCRecord.RECORD_TYPE,
                json.dumps(
                    {
                        "state": "request-sent",
                        "request": test_rpc_request,
                    }
                ),
                test_tags,
                "test-record-id",
            )
        )

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_get_record(self.request)
