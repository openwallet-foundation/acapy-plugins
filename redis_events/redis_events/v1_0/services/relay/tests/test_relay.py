import json
import os

import aiohttp
import redis
from asynctest import PropertyMock
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from .. import relay as test_module
from ..relay import HttpRelay, WSRelay

test_retry_msg_a = str.encode(json.dumps(
    ["invalid", "list", "require", "dict"]))
test_retry_msg_b = str.encode(
    json.dumps(
        {
            "response_data": {
                "content-type": "application/json",
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9",
            },
        }
    )
)
test_retry_msg_c = str.encode(
    json.dumps(
        {
            "response_data": {
                "content-type": "application/json",
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9",
            },
            "txn_id": "test123",
        }
    )
)
test_retry_msg_d = str.encode(
    json.dumps(
        {
            "txn_id": "test123",
        }
    )
)


class TestRedisHTTPHandler(AsyncTestCase):
    async def test_run(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            HttpRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "start", async_mock.CoroutineMock()
        ):
            HttpRelay.running = False
            relay = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(side_effect=redis.exceptions.RedisError),
        ) as mock_redis, async_mock.patch.object(
            HttpRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "start", async_mock.CoroutineMock()
        ):
            HttpRelay.running = False
            relay = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

    async def test_main(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            HttpRelay, "start", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "run", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "start", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "run", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            test_module, "start_status_endpoints_server", async_mock.CoroutineMock()
        ) as mock_status_endpoint, async_mock.patch.dict(
            os.environ,
            {
                "REDIS_SERVER_URL": "test",
                "STATUS_ENDPOINT_HOST": "5002",
                "STATUS_ENDPOINT_PORT": "0.0.0.0",
                "STATUS_ENDPOINT_API_KEY": "test1234",
                "INBOUND_TRANSPORT_CONFIG": '[["http", "0.0.0.0", "8021"],["ws", "0.0.0.0", "8023"]]',
            },
        ):
            sentinel = PropertyMock(return_value=False)
            HttpRelay.running = sentinel
            WSRelay.running = sentinel
            await test_module.main()

    async def test_main_x(self):
        with async_mock.patch.dict(
            os.environ,
            {
                "REDIS_SERVER_URL": "test",
                "STATUS_ENDPOINT_HOST": "5002",
                "STATUS_ENDPOINT_PORT": "0.0.0.0",
                "STATUS_ENDPOINT_API_KEY": "test1234",
            },
        ):
            with self.assertRaises(SystemExit):
                await test_module.main()

        with async_mock.patch.dict(
            os.environ,
            {
                "STATUS_ENDPOINT_HOST": "5002",
                "STATUS_ENDPOINT_PORT": "0.0.0.0",
                "STATUS_ENDPOINT_API_KEY": "test1234",
                "INBOUND_TRANSPORT_CONFIG": '[["http", "0.0.0.0", "8021"],["ws", "0.0.0.0", "8023"]]',
            },
        ):
            with self.assertRaises(SystemExit):
                await test_module.main()

        with async_mock.patch.dict(
            os.environ,
            {
                "REDIS_SERVER_URL": "test",
                "STATUS_ENDPOINT_HOST": "5002",
                "STATUS_ENDPOINT_PORT": "0.0.0.0",
                "STATUS_ENDPOINT_API_KEY": "test1234",
                "INBOUND_TRANSPORT_CONFIG": '[["test", "0.0.0.0", "8021"]]',
            },
        ):
            with self.assertRaises(SystemExit):
                await test_module.main()

        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(
                ping=async_mock.CoroutineMock(
                    side_effect=redis.exceptions.RedisError)
            ),
        ) as mock_redis, async_mock.patch.object(
            HttpRelay, "start", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            HttpRelay, "run", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "start", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "run", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            test_module, "start_status_endpoints_server", async_mock.CoroutineMock()
        ) as mock_status_endpoint, async_mock.patch.dict(
            os.environ,
            {
                "REDIS_SERVER_URL": "test",
                "STATUS_ENDPOINT_HOST": "5002",
                "STATUS_ENDPOINT_PORT": "0.0.0.0",
                "STATUS_ENDPOINT_API_KEY": "test1234",
                "INBOUND_TRANSPORT_CONFIG": '[["http", "0.0.0.0", "8021"],["ws", "0.0.0.0", "8023"]]',
            },
        ):
            await test_module.main()

    async def test_stop(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module.web,
            "TCPSite",
            async_mock.MagicMock(stop=async_mock.CoroutineMock()),
        ) as mock_site:
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.site = async_mock.MagicMock(
                stop=async_mock.CoroutineMock())
            service.redis = mock_redis
            await service.stop()

    async def test_start(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    ping=async_mock.CoroutineMock(),
                )
            ),
        ) as mock_redis, async_mock.patch.object(
            test_module.web,
            "TCPSite",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    stop=async_mock.CoroutineMock(),
                    start=async_mock.CoroutineMock(),
                )
            ),
        ), async_mock.patch.object(
            test_module.web.AppRunner,
            "setup",
            async_mock.CoroutineMock(),
        ):
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            await service.start()

    async def test_process_direct_response(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            mock_redis.blpop = async_mock.CoroutineMock(
                side_effect=[
                    (None, test_retry_msg_a),
                    (None, test_retry_msg_b),
                    (None, test_retry_msg_c),
                    None,
                    test_module.RedisError,
                    (None, test_retry_msg_d),
                ]
            )
            mock_redis.ping = async_mock.CoroutineMock()
            sentinel = PropertyMock(
                side_effect=[True, True, True, True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            service.redis = mock_redis
            assert service.direct_response_txn_request_map == {}
            await service.process_direct_responses()
            assert service.direct_response_txn_request_map != {}

    async def test_get_direct_response(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(side_effect=[True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            service.timedelay_s = 0.1
            service.direct_response_txn_request_map = {
                "txn_123": b"test",
                "txn_124": b"test2",
            }
            await service.get_direct_responses("txn_321")
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(side_effect=[True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            service.timedelay_s = 0.1
            service.direct_response_txn_request_map = {
                "txn_123": b"test",
                "txn_124": b"test2",
            }
            await service.get_direct_responses("txn_123") == b"test"
            await service.get_direct_responses("txn_124") == b"test2"

    async def test_message_handler(self):
        mock_request = async_mock.MagicMock(
            headers={"content-type": "application/json"},
            text=async_mock.CoroutineMock(
                return_value=str.encode(json.dumps({"test": "...."})).decode()
            ),
            host="test",
            remote="test",
        )
        sentinel = PropertyMock(side_effect=[True, False])
        HttpRelay.running = sentinel
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            assert (await service.message_handler(mock_request)).status == 200
        with async_mock.patch.object(
            HttpRelay,
            "get_direct_responses",
            async_mock.CoroutineMock(
                return_value={
                    "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
                }
            ),
        ), async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            mock_request = async_mock.MagicMock(
                headers={"content-type": "..."},
                read=async_mock.CoroutineMock(
                    return_value=str.encode(
                        json.dumps(
                            {"test": "....", "~transport": {"return_route": "..."}}
                        )
                    )
                ),
                host="test",
                remote="test",
            )
            assert (await service.message_handler(mock_request)).status == 200
        with async_mock.patch.object(
            HttpRelay,
            "get_direct_responses",
            async_mock.CoroutineMock(
                side_effect=test_module.asyncio.TimeoutError),
        ), async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            mock_request = async_mock.MagicMock(
                headers={"content-type": "..."},
                read=async_mock.CoroutineMock(
                    return_value=json.dumps(
                        {
                            "content-type": "application/json",
                            "test": "....",
                            "~transport": {"return_route": "..."},
                        }
                    )
                ),
                host="test",
                remote="test",
            )
            assert (await service.message_handler(mock_request)).status == 200

    async def test_message_handler_x(self):
        with async_mock.patch.object(
            HttpRelay,
            "get_direct_responses",
            async_mock.CoroutineMock(
                side_effect=test_module.asyncio.TimeoutError),
        ), async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock(
                side_effect=[test_module.RedisError, None]
            )
            service.redis = mock_redis
            mock_request = async_mock.MagicMock(
                headers={"content-type": "..."},
                read=async_mock.CoroutineMock(
                    return_value=str.encode(
                        json.dumps(
                            {"test": "....", "~transport": {"return_route": "..."}}
                        )
                    )
                ),
                host="test",
                remote="test",
            )
            await service.message_handler(mock_request)

            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock(
                side_effect=[test_module.RedisError, None]
            )
            service.redis = mock_redis
            mock_request = async_mock.MagicMock(
                headers={"content-type": "..."},
                read=async_mock.CoroutineMock(
                    return_value=str.encode(json.dumps({"test": "...."}))
                ),
                host="test",
                remote="test",
            )
            await service.message_handler(mock_request)

    async def test_invite_handler(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            await service.invite_handler(async_mock.MagicMock(query={"c_i": ".."}))
            await service.invite_handler(async_mock.MagicMock(query={}))

    async def test_is_running(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(return_value=True)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(ping=async_mock.CoroutineMock())
            service.redis = mock_redis
            service.running = True
            assert await service.is_running()
            sentinel = PropertyMock(return_value=False)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(ping=async_mock.CoroutineMock())
            service.redis = mock_redis
            service.running = False
            assert not await service.is_running()
            sentinel = PropertyMock(return_value=True)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(
                ping=async_mock.CoroutineMock(
                    side_effect=redis.exceptions.RedisError)
            )
            service.redis = mock_redis
            service.running = True
            assert not await service.is_running()


class TestRedisWSHandler(AsyncTestCase):
    async def test_run(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            WSRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "start", async_mock.CoroutineMock()
        ):
            WSRelay.running = False
            relay = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(side_effect=redis.exceptions.RedisError),
        ) as mock_redis, async_mock.patch.object(
            WSRelay, "process_direct_responses", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            WSRelay, "start", async_mock.CoroutineMock()
        ):
            WSRelay.running = False
            relay = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

    async def test_stop(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module.web,
            "TCPSite",
            async_mock.MagicMock(stop=async_mock.CoroutineMock()),
        ) as mock_site:
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.site = async_mock.MagicMock(
                stop=async_mock.CoroutineMock())
            service.redis = mock_redis
            await service.stop()

    async def test_start(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module.web,
            "TCPSite",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    stop=async_mock.CoroutineMock(),
                    start=async_mock.CoroutineMock(),
                )
            ),
        ), async_mock.patch.object(
            test_module.web.AppRunner,
            "setup",
            async_mock.CoroutineMock(),
        ):
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.start()

    async def test_process_direct_response(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            mock_redis.blpop = async_mock.CoroutineMock(
                side_effect=[
                    (None, test_retry_msg_a),
                    (None, test_retry_msg_b),
                    (None, test_retry_msg_c),
                    test_module.RedisError,
                    (None, test_retry_msg_d),
                ]
            )
            mock_redis.ping = async_mock.CoroutineMock()
            sentinel = PropertyMock(
                side_effect=[True, True, True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            service.redis = mock_redis
            assert service.direct_response_txn_request_map == {}
            await service.process_direct_responses()
            assert service.direct_response_txn_request_map != {}

    async def test_get_direct_response(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(side_effect=[True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            service.redis = mock_redis
            service.direct_response_txn_request_map = {
                "txn_123": b"test",
                "txn_124": b"test2",
            }
            await service.get_direct_responses("txn_321")
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(side_effect=[True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            service.redis = mock_redis
            service.direct_response_txn_request_map = {
                "txn_123": b"test",
                "txn_124": b"test2",
            }
            await service.get_direct_responses("txn_123") == b"test"
            await service.get_direct_responses("txn_124") == b"test2"

    async def test_message_handler_a(self):
        mock_request = async_mock.MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=str.encode(
                json.dumps({"test": "....", "~transport": {
                           "return_route": "..."}})
            ),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            WSRelay,
            "get_direct_responses",
            autospec=True,
        ) as mock_get_direct_responses, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_b(self):
        mock_request = async_mock.MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps(
                {"test": "....", "~transport": {"return_route": "..."}}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            WSRelay,
            "get_direct_responses",
            autospec=True,
        ) as mock_get_direct_responses, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_c(self):
        mock_request = async_mock.MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "...."}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            WSRelay,
            "get_direct_responses",
            autospec=True,
        ) as mock_get_direct_responses, async_mock.patch.object(
            redis.cluster.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_x(self):
        mock_request = async_mock.MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps(
                {"test": "....", "~transport": {"return_route": "..."}}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            WSRelay,
            "get_direct_responses",
            autospec=True,
        ) as mock_get_direct_responses, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            mock_get_direct_responses.side_effect = test_module.asyncio.TimeoutError
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps(
                {"test": "....", "~transport": {"return_route": "..."}}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            WSRelay,
            "get_direct_responses",
            autospec=True,
        ) as mock_get_direct_responses, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock(
                side_effect=[test_module.RedisError, None]
            )
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.ERROR.value,
            data=json.dumps({"test": "...."}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, True]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = async_mock.MagicMock(
            type="invlaid",
            data=json.dumps({"test": "...."}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, True]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = async_mock.MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "...."}),
        )

        with async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "prepare",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "receive",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "closed",
            PropertyMock(side_effect=[False, False, True, False]),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "close",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "exception",
            async_mock.MagicMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_bytes",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.web.WebSocketResponse,
            "send_str",
            async_mock.CoroutineMock(),
        ), async_mock.patch.object(
            test_module.asyncio,
            "get_event_loop",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    run_until_complete=async_mock.MagicMock(),
                    create_task=async_mock.MagicMock(
                        return_value=async_mock.MagicMock(
                            done=async_mock.MagicMock(return_value=True),
                            result=async_mock.MagicMock(return_value=mock_msg),
                        )
                    ),
                )
            ),
        ) as mock_get_event_loop, async_mock.patch.object(
            test_module.asyncio, "wait", async_mock.CoroutineMock()
        ) as mock_wait, async_mock.patch.object(
            test_module.asyncio,
            "wait_for",
            async_mock.CoroutineMock(return_value=b"{}"),
        ) as mock_wait_for, async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis, async_mock.patch.object(
            test_module,
            "process_payload_recip_key",
            async_mock.CoroutineMock(
                return_value=("acapy_inbound_input_recip_key",
                              async_mock.MagicMock())
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = async_mock.CoroutineMock()
            mock_redis.rpush = async_mock.CoroutineMock(
                side_effect=[test_module.RedisError, None]
            )
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_is_running(self):
        with async_mock.patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            async_mock.MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(return_value=True)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(ping=async_mock.CoroutineMock())
            service.redis = mock_redis
            service.running = True
            assert await service.is_running()
            sentinel = PropertyMock(return_value=False)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(ping=async_mock.CoroutineMock())
            service.redis = mock_redis
            service.running = False
            assert not await service.is_running()
            sentinel = PropertyMock(return_value=True)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = async_mock.MagicMock(
                ping=async_mock.CoroutineMock(
                    side_effect=redis.exceptions.RedisError)
            )
            service.redis = mock_redis
            service.running = True
            assert not await service.is_running()

    def test_b64_to_bytes(self):
        test_module.b64_to_bytes(
            "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9", urlsafe=False
        ) == b'{"test": "...", "test2": "test2"}'

    def test_init(self):
        with async_mock.patch.object(
            test_module, "__name__", "__main__"
        ), async_mock.patch.object(
            test_module, "signal", autospec=True
        ), async_mock.patch.object(
            test_module,
            "asyncio",
            async_mock.MagicMock(
                get_event_loop=async_mock.MagicMock(
                    add_signal_handler=async_mock.MagicMock(),
                    run_until_complete=async_mock.MagicMock(),
                    close=async_mock.MagicMock(),
                ),
                ensure_future=async_mock.MagicMock(
                    cancel=async_mock.MagicMock(),
                ),
                CancelledError=async_mock.MagicMock(),
            ),
        ):
            test_module.init()
