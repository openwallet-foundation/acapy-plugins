import json

from aiohttp import web
from asynctest import mock as async_mock
from asynctest import TestCase as AsyncTestCase

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError

from rpc.v1_0.models import DRPCRecord, DRPCRecordSchema
import rpc.v1_0.routes as test_module

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


def generate_mock_drpc_request_message(request):
    schema = test_module.DRPCRequestMessageSchema()
    msg = schema.load({"request": request})
    msg._id = "test-request-message-id"
    msg._type = "https://didcomm.org/drpc/1.0/request"
    return msg


def generate_mock_drpc_response_message(thread_id, response):
    schema = test_module.DRPCResponseMessageSchema()
    msg = schema.load({"response": response})
    msg._id = "test-response-message-id"
    msg._type = "https://didcomm.org/drpc/1.0/response"
    msg.assign_thread_id(thread_id)
    return msg


class MockConnRecord:
    def __init__(self, connection_id, is_ready):
        self.connection_id = connection_id
        self.is_ready = is_ready


class TestDRPCRoutes(AsyncTestCase):
    def setUp(self):
        self.session_inject = {}

        self.storage = async_mock.MagicMock()
        self.session_inject[test_module.BaseStorage] = self.storage

        self.context = AdminRequestContext.test_context(self.session_inject)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": async_mock.CoroutineMock(),
        }
        self.request = async_mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, key: self.request_dict[key],
        )

    async def test_get_empty_drpc_record_list(self):
        self.storage.find_all_records = async_mock.CoroutineMock(return_value=[])

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
            await test_module.drpc_get_records(self.request)
            mock_response.assert_called_once_with({"results": []})

    async def test_get_drpc_record_list(self):
        self.storage.find_all_records = async_mock.CoroutineMock(
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

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
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
        self.storage.find_all_records = async_mock.CoroutineMock(
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

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
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
        self.storage.get_record = async_mock.CoroutineMock(
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

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
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

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @async_mock.patch.object(
        test_module,
        "DRPCRequestMessage",
        return_value=generate_mock_drpc_request_message(test_rpc_request),
    )
    async def test_send_drpc_request_success(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={"request": test_rpc_request}
        )

        self.storage.add_record = async_mock.CoroutineMock()
        self.storage.update_record = async_mock.CoroutineMock()

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
            await test_module.drpc_send_request(self.request)
            mock_response.assert_called_once_with(
                {
                    "request": test_rpc_request,
                    "@id": "test-request-message-id",
                    "@type": "https://didcomm.org/drpc/1.0/request",
                }
            )

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @async_mock.patch.object(
        test_module.DRPCRecord,
        "retrieve_by_connection_and_thread",
        return_value=DRPCRecordSchema().load(
            {"state": "request-received", "request": test_rpc_request}
        ),
    )
    @async_mock.patch.object(
        test_module,
        "DRPCResponseMessage",
        return_value=generate_mock_drpc_response_message(
            "test-request-message-id", test_rpc_response
        ),
    )
    async def test_send_drpc_response_success(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "thread_id": "test-request-message-id",
                "response": test_rpc_response,
            }
        )

        self.storage.find_all_records = async_mock.CoroutineMock()
        self.storage.update_record = async_mock.CoroutineMock()

        with async_mock.patch.object(test_module.web, "json_response") as mock_response:
            await test_module.drpc_send_response(self.request)
            mock_response.assert_called_once_with(
                {
                    "response": test_rpc_response,
                    "@id": "test-response-message-id",
                    "@type": "https://didcomm.org/drpc/1.0/response",
                    "~thread": {"thid": "test-request-message-id"},
                }
            )

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        side_effect=StorageNotFoundError(),
    )
    async def test_http_not_found_thrown_on_connection_not_found_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "request": test_rpc_request,
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.add_record = async_mock.CoroutineMock()
        self.storage.update_record = async_mock.CoroutineMock()

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_request(self.request)

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_response(self.request)

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    async def test_http_internal_server_error_thrown_on_add_storage_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={"request": test_rpc_request}
        )

        self.storage.add_record = async_mock.CoroutineMock(side_effect=StorageError())

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_request(self.request)

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @async_mock.patch.object(
        test_module.DRPCRecord,
        "retrieve_by_connection_and_thread",
        return_value=DRPCRecordSchema().load(
            {"state": "request-received", "request": test_rpc_request}
        ),
    )
    async def test_http_internal_server_error_thrown_on_update_storage_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "request": test_rpc_request,
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.add_record = async_mock.CoroutineMock()
        self.storage.update_record = async_mock.CoroutineMock(
            side_effect=StorageError()
        )

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_request(self.request)

        with self.assertRaises(web.HTTPInternalServerError):
            await test_module.drpc_send_response(self.request)

    @async_mock.patch.object(
        test_module.ConnRecord,
        "retrieve_by_id",
        return_value=MockConnRecord("test-connection-id", True),
    )
    @async_mock.patch.object(
        test_module.DRPCRecord,
        "retrieve_by_connection_and_thread",
        side_effect=StorageNotFoundError(),
    )
    async def test_http_not_found_thrown_on_drpc_record_not_found_error(self, *_):
        self.request.match_info = {"conn_id": "test-connection-id"}
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "response": test_rpc_response,
                "thread_id": "test-thread-id",
            }
        )

        self.storage.update_record = async_mock.CoroutineMock()

        with self.assertRaises(web.HTTPNotFound):
            await test_module.drpc_send_response(self.request)

    @async_mock.patch.object(
        test_module.DRPCRecord,
        "from_storage",
        side_effect=BaseModelError(),
    )
    async def test_http_internal_server_error_thrown_on_drpc_get_records(self, *_):
        self.storage.find_all_records = async_mock.CoroutineMock(
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

    @async_mock.patch.object(
        test_module.DRPCRecord,
        "from_storage",
        side_effect=BaseModelError(),
    )
    async def test_http_not_found_thrown_on_drpc_get_record(self, *_):
        self.request.match_info = {"record_id": "test-record-id"}

        self.storage.get_record = async_mock.CoroutineMock(
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
