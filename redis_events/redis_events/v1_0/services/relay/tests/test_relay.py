import json
import os
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import aiohttp
import redis

from .. import relay as test_module
from ..relay import HttpRelay, WSRelay

test_retry_msg_a = str.encode(json.dumps(["invalid", "list", "require", "dict"]))
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


class TestRedisHTTPHandler(IsolatedAsyncioTestCase):
    async def test_run(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(HttpRelay, "process_direct_responses", AsyncMock()),
            patch.object(HttpRelay, "start", AsyncMock()),
        ):
            HttpRelay.running = False
            relay = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(side_effect=redis.exceptions.RedisError),
            ) as mock_redis,
            patch.object(HttpRelay, "process_direct_responses", AsyncMock()),
            patch.object(HttpRelay, "start", AsyncMock()),
        ):
            HttpRelay.running = False
            relay = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

    async def test_main(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(HttpRelay, "start", AsyncMock()),
            patch.object(HttpRelay, "process_direct_responses", AsyncMock()),
            patch.object(HttpRelay, "run", AsyncMock()),
            patch.object(WSRelay, "start", AsyncMock()),
            patch.object(WSRelay, "process_direct_responses", AsyncMock()),
            patch.object(WSRelay, "run", AsyncMock()),
            patch.object(
                test_module, "start_status_endpoints_server", AsyncMock()
            ) as mock_status_endpoint,
            patch.dict(
                os.environ,
                {
                    "REDIS_SERVER_URL": "test",
                    "STATUS_ENDPOINT_HOST": "5002",
                    "STATUS_ENDPOINT_PORT": "0.0.0.0",
                    "STATUS_ENDPOINT_API_KEY": "test1234",
                    "INBOUND_TRANSPORT_CONFIG": '[["http", "0.0.0.0", "8021"],["ws", "0.0.0.0", "8023"]]',
                },
            ),
        ):
            sentinel = PropertyMock(return_value=False)
            HttpRelay.running = sentinel
            WSRelay.running = sentinel
            await test_module.main()

    async def test_main_x(self):
        with patch.dict(
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

        with patch.dict(
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

        with patch.dict(
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

        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(ping=AsyncMock(side_effect=redis.exceptions.RedisError)),
            ) as mock_redis,
            patch.object(HttpRelay, "start", AsyncMock()),
            patch.object(HttpRelay, "process_direct_responses", AsyncMock()),
            patch.object(HttpRelay, "run", AsyncMock()),
            patch.object(WSRelay, "start", AsyncMock()),
            patch.object(WSRelay, "process_direct_responses", AsyncMock()),
            patch.object(WSRelay, "run", AsyncMock()),
            patch.object(
                test_module, "start_status_endpoints_server", AsyncMock()
            ) as mock_status_endpoint,
            patch.dict(
                os.environ,
                {
                    "REDIS_SERVER_URL": "test",
                    "STATUS_ENDPOINT_HOST": "5002",
                    "STATUS_ENDPOINT_PORT": "0.0.0.0",
                    "STATUS_ENDPOINT_API_KEY": "test1234",
                    "INBOUND_TRANSPORT_CONFIG": '[["http", "0.0.0.0", "8021"],["ws", "0.0.0.0", "8023"]]',
                },
            ),
        ):
            await test_module.main()

    async def test_stop(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module.web,
                "TCPSite",
                MagicMock(stop=AsyncMock()),
            ) as mock_site,
        ):
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.site = MagicMock(stop=AsyncMock())
            service.redis = mock_redis
            await service.stop()

    async def test_start(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(
                    return_value=MagicMock(
                        ping=AsyncMock(),
                    )
                ),
            ) as mock_redis,
            patch.object(
                test_module.web,
                "TCPSite",
                MagicMock(
                    return_value=MagicMock(
                        stop=AsyncMock(),
                        start=AsyncMock(),
                    )
                ),
            ),
            patch.object(
                test_module.web.AppRunner,
                "setup",
                AsyncMock(),
            ),
        ):
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            await service.start()

    async def test_process_direct_response(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            mock_redis.blpop = AsyncMock(
                side_effect=[
                    (None, test_retry_msg_a),
                    (None, test_retry_msg_b),
                    (None, test_retry_msg_c),
                    None,
                    test_module.RedisError,
                    (None, test_retry_msg_d),
                ]
            )
            mock_redis.ping = AsyncMock()
            sentinel = PropertyMock(side_effect=[True, True, True, True, True, False])
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
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
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
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
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
        mock_request = MagicMock(
            headers={"content-type": "application/json"},
            text=AsyncMock(
                return_value=str.encode(json.dumps({"test": "...."})).decode()
            ),
            host="test",
            remote="test",
        )
        sentinel = PropertyMock(side_effect=[True, False])
        HttpRelay.running = sentinel
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            assert (await service.message_handler(mock_request)).status == 200
        with (
            patch.object(
                HttpRelay,
                "get_direct_responses",
                AsyncMock(
                    return_value={
                        "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
                    }
                ),
            ),
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            mock_request = MagicMock(
                headers={"content-type": "..."},
                read=AsyncMock(
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
        with (
            patch.object(
                HttpRelay,
                "get_direct_responses",
                AsyncMock(side_effect=test_module.asyncio.TimeoutError),
            ),
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            mock_request = MagicMock(
                headers={"content-type": "..."},
                read=AsyncMock(
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
        with (
            patch.object(
                HttpRelay,
                "get_direct_responses",
                AsyncMock(side_effect=test_module.asyncio.TimeoutError),
            ),
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock(side_effect=[test_module.RedisError, None])
            service.redis = mock_redis
            mock_request = MagicMock(
                headers={"content-type": "..."},
                read=AsyncMock(
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
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock(side_effect=[test_module.RedisError, None])
            service.redis = mock_redis
            mock_request = MagicMock(
                headers={"content-type": "..."},
                read=AsyncMock(return_value=str.encode(json.dumps({"test": "...."}))),
                host="test",
                remote="test",
            )
            await service.message_handler(mock_request)

    async def test_invite_handler(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.redis = mock_redis
            await service.invite_handler(MagicMock(query={"c_i": ".."}))
            await service.invite_handler(MagicMock(query={}))

    async def test_is_running(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(return_value=True)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = True
            assert await service.is_running()
            sentinel = PropertyMock(return_value=False)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = False
            assert not await service.is_running()
            sentinel = PropertyMock(return_value=True)
            HttpRelay.running = sentinel
            service = HttpRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(
                ping=AsyncMock(side_effect=redis.exceptions.RedisError)
            )
            service.redis = mock_redis
            service.running = True
            assert not await service.is_running()


class TestRedisWSHandler(IsolatedAsyncioTestCase):
    async def test_run(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(WSRelay, "process_direct_responses", AsyncMock()),
            patch.object(WSRelay, "start", AsyncMock()),
        ):
            WSRelay.running = False
            relay = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(side_effect=redis.exceptions.RedisError),
            ) as mock_redis,
            patch.object(WSRelay, "process_direct_responses", AsyncMock()),
            patch.object(WSRelay, "start", AsyncMock()),
        ):
            WSRelay.running = False
            relay = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            await relay.run()

    async def test_stop(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module.web,
                "TCPSite",
                MagicMock(stop=AsyncMock()),
            ) as mock_site,
        ):
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.site = MagicMock(stop=AsyncMock())
            service.redis = mock_redis
            await service.stop()

    async def test_start(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module.web,
                "TCPSite",
                MagicMock(
                    return_value=MagicMock(
                        stop=AsyncMock(),
                        start=AsyncMock(),
                    )
                ),
            ),
            patch.object(
                test_module.web.AppRunner,
                "setup",
                AsyncMock(),
            ),
        ):
            sentinel = PropertyMock(side_effect=[True, True, True, False])
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.start()

    async def test_process_direct_response(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            mock_redis.blpop = AsyncMock(
                side_effect=[
                    (None, test_retry_msg_a),
                    (None, test_retry_msg_b),
                    (None, test_retry_msg_c),
                    test_module.RedisError,
                    (None, test_retry_msg_d),
                ]
            )
            mock_redis.ping = AsyncMock()
            sentinel = PropertyMock(side_effect=[True, True, True, True, False])
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
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
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
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
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
        mock_request = MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=str.encode(
                json.dumps({"test": "....", "~transport": {"return_route": "..."}})
            ),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                WSRelay,
                "get_direct_responses",
                autospec=True,
            ) as mock_get_direct_responses,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_b(self):
        mock_request = MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "....", "~transport": {"return_route": "..."}}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                WSRelay,
                "get_direct_responses",
                autospec=True,
            ) as mock_get_direct_responses,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_c(self):
        mock_request = MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "...."}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                WSRelay,
                "get_direct_responses",
                autospec=True,
            ) as mock_get_direct_responses,
            patch.object(
                redis.cluster.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_message_handler_x(self):
        mock_request = MagicMock(
            host="test",
            remote="test",
        )
        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "....", "~transport": {"return_route": "..."}}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                WSRelay,
                "get_direct_responses",
                autospec=True,
            ) as mock_get_direct_responses,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            mock_get_direct_responses.side_effect = test_module.asyncio.TimeoutError
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "....", "~transport": {"return_route": "..."}}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                WSRelay,
                "get_direct_responses",
                autospec=True,
            ) as mock_get_direct_responses,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            mock_get_direct_responses.return_value = {
                "response": "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9"
            }
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock(side_effect=[test_module.RedisError, None])
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.ERROR.value,
            data=json.dumps({"test": "...."}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, True]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = MagicMock(
            type="invlaid",
            data=json.dumps({"test": "...."}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, True]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock()
            service.redis = mock_redis
            await service.message_handler(mock_request)

        mock_msg = MagicMock(
            type=aiohttp.WSMsgType.TEXT.value,
            data=json.dumps({"test": "...."}),
        )

        with (
            patch.object(
                test_module.web.WebSocketResponse,
                "prepare",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "receive",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "closed",
                PropertyMock(side_effect=[False, False, True, False]),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "close",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "exception",
                MagicMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_bytes",
                AsyncMock(),
            ),
            patch.object(
                test_module.web.WebSocketResponse,
                "send_str",
                AsyncMock(),
            ),
            patch.object(
                test_module.asyncio,
                "get_event_loop",
                MagicMock(
                    return_value=MagicMock(
                        run_until_complete=MagicMock(),
                        create_task=MagicMock(
                            return_value=MagicMock(
                                done=MagicMock(return_value=True),
                                result=MagicMock(return_value=mock_msg),
                            )
                        ),
                    )
                ),
            ) as mock_get_event_loop,
            patch.object(test_module.asyncio, "wait", AsyncMock()) as mock_wait,
            patch.object(
                test_module.asyncio,
                "wait_for",
                AsyncMock(return_value=b"{}"),
            ) as mock_wait_for,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(
                test_module,
                "process_payload_recip_key",
                AsyncMock(return_value=("acapy_inbound_input_recip_key", MagicMock())),
            ),
        ):
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            service.timedelay_s = 0.1
            mock_redis.blpop = AsyncMock()
            mock_redis.rpush = AsyncMock(side_effect=[test_module.RedisError, None])
            service.redis = mock_redis
            await service.message_handler(mock_request)

    async def test_is_running(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(return_value=True)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = True
            assert await service.is_running()
            sentinel = PropertyMock(return_value=False)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = False
            assert not await service.is_running()
            sentinel = PropertyMock(return_value=True)
            WSRelay.running = sentinel
            service = WSRelay(
                "test", "test", "8080", "direct_resp_topic", "inbound_msg_topic"
            )
            mock_redis = MagicMock(
                ping=AsyncMock(side_effect=redis.exceptions.RedisError)
            )
            service.redis = mock_redis
            service.running = True
            assert not await service.is_running()

    def test_b64_to_bytes(self):
        test_module.b64_to_bytes(
            "eyJ0ZXN0IjogIi4uLiIsICJ0ZXN0MiI6ICJ0ZXN0MiJ9", urlsafe=False
        ) == b'{"test": "...", "test2": "test2"}'

    def test_init(self):
        with (
            patch.object(test_module, "__name__", "__main__"),
            patch.object(test_module, "signal", autospec=True),
            patch.object(
                test_module,
                "asyncio",
                MagicMock(
                    get_event_loop=MagicMock(
                        add_signal_handler=MagicMock(),
                        run_until_complete=MagicMock(),
                        close=MagicMock(),
                    ),
                    ensure_future=MagicMock(
                        cancel=MagicMock(),
                    ),
                    CancelledError=MagicMock(),
                ),
            ),
        ):
            test_module.init()
