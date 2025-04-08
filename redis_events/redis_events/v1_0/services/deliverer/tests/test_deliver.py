import asyncio
import base64
import json
import os
import string
from time import time
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import aiohttp
import redis

from .. import deliver as test_module
from ..deliver import Deliverer, main

PAYLOAD_B64 = """
    eyJwcm90ZWN0ZWQiOiAiZXlKbGJtTWlPaUFpZUdOb1lXTm9ZVEl3Y0c5c2VURXpNRFZmYVdWM
    FppSXNJQ0owZVhBaU9pQWlTbGROTHpFdU1DSXNJQ0poYkdjaU9pQWlRWFYwYUdOeWVYQjBJaX
    dnSW5KbFkybHdhV1Z1ZEhNaU9pQmJleUpsYm1OeWVYQjBaV1JmYTJWNUlqb2dJakZqWjNsMFF
    tMTNNM0V4YUdkaVZ6Qkpiak50U0c4MldXaExUMnRwUnpWRWVUaHJSakpJV2pZeGNUSnZXV00z
    Ym10dVN6bE9TVWMyU0VobFUyTm9lV0VpTENBaWFHVmhaR1Z5SWpvZ2V5SnJhV1FpT2lBaU5FU
    kNTalJhY0RnMU1XZHFlazUwU20xdGIwVTVOMWR4Vm5KWFRqTTJlVnBTWVVkcFpqUkJSM0o0ZD
    FFaUxDQWljMlZ1WkdWeUlqb2dJak5XY0hsU2NVRlpUV3N5Tms1RmMwUXpObU5mWjJnMFZIazB
    aamd3TUd4RFJHRXdNMWxsUlc1bVJYQm1WMmhKTFdkelpFY3RWR1JrTVdWTmFEbFpTWG8zTkhS
    RlN6SnNSMVZhVFhwZk5HdDFkMEpUVWtvMFRGOWhkMVJLUVZWVmQydFRWbmhyTXpSblVWVmZOV
    2RyZDFSa09FWTFUa0ZsU1U1UVZTSXNJQ0pwZGlJNklDSnFWVkpDUW1OaVQzZzNOa05zVmw4eG
    F6aFJNMjlyVW5KdFJHUTFhM0JwUWlKOWZWMTkiLCAiaXYiOiAiTVdnR3VRNF9ab2dxVVJUbiI
    sICJjaXBoZXJ0ZXh0IjogIlVNTGFQOU13ZF9wOFR1bWdwcVZWQWZTSWZXc1g3a0lWLUR4Rndf
    VHRTQ2pWdTVTbG5RYmtkTVJLd3VyZGI1dmd6Q0tUNUFybFV0WEFMMm1sSUlpUGpSYzVmSzhLc
    013S0dFemkycEtrdmxDN1EzUXRKWTE5WmVTSjlYMGlUOWxOamNEM25KS0o1bzlkSjhVWGZpNU
    80ZEtaLWxlVy1qOHlzTEFTSTh1eEZYVVNoUmxlNy03bm5HZkZnRlZBRjNaWVpqNlRXUUJrdkd
    SUk96TzMwTHNEWHBzalNqMWZfd056RWdxTmpPMERZemRKa0lBNm1BQ1AiLCAidGFnIjogImVB
    ZVFiakktVmpkN21hcWdTNElGTlEifQ==
"""

test_msg_a = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test"},
                "service": {"url": "http://localhost:9000"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_b = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "ws://localhost:9001"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_c = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "http://localhost:9002"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_d = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "http://localhost:9003"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
                "retries": 6,
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_e = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "http://localhost:9004"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
                "retry_time": int(time()),
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_err_a = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_err_b = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "http://localhost:9005"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
                "retries": 6,
            }
        ),
        encoding="utf-8",
    ),
)
test_msg_err_c = (
    None,
    str.encode(
        json.dumps(
            {
                "headers": {"content-type": "test1"},
                "service": {"url": "test://localhost:9002"},
                "payload": base64.urlsafe_b64encode(
                    (string.digits + string.ascii_letters).encode(encoding="utf-8")
                ).decode(),
            }
        ),
        encoding="utf-8",
    ),
)


class TestRedisHandler(IsolatedAsyncioTestCase):
    async def test_main(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", autospec=True),
            patch.object(Deliverer, "process_retries", autospec=True),
            patch.dict(
                os.environ,
                {
                    "REDIS_SERVER_URL": "test",
                    "TOPIC_PREFIX": "acapy",
                    "STATUS_ENDPOINT_HOST": "5002",
                    "STATUS_ENDPOINT_PORT": "0.0.0.0",
                    "STATUS_ENDPOINT_API_KEY": "test1234",
                },
            ),
            patch.object(
                test_module, "start_status_endpoints_server", AsyncMock()
            ) as mock_status_endpoint,
        ):
            mock_redis.return_value = MagicMock()
            await main()
            mock_status_endpoint.assert_called_once()

    async def test_main_x(self):
        with self.assertRaises(SystemExit):
            await main()

        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", autospec=True),
            patch.object(Deliverer, "process_retries", autospec=True),
            patch.object(
                test_module, "start_status_endpoints_server", AsyncMock()
            ) as mock_status_endpoint,
            patch.dict(
                os.environ,
                {
                    "REDIS_SERVER_URL": "test",
                },
            ),
        ):
            await main()
            assert mock_status_endpoint.call_count == 0
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", autospec=True),
            patch.object(Deliverer, "process_retries", autospec=True),
            patch.object(
                test_module, "start_status_endpoints_server", AsyncMock()
            ) as mock_status_endpoint,
            patch.dict(
                os.environ,
                {
                    "REDIS_SERVER_URL": "test",
                    "STATUS_ENDPOINT_HOST": "5002",
                    "STATUS_ENDPOINT_PORT": "0.0.0.0",
                },
            ),
        ):
            await main()
            assert mock_status_endpoint.call_count == 0
        sentinel = PropertyMock(return_value=False)
        Deliverer.running = sentinel
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(ping=AsyncMock(side_effect=redis.exceptions.RedisError)),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", autospec=True),
            patch.object(Deliverer, "process_retries", autospec=True),
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
                },
            ),
        ):
            await main()
            assert mock_status_endpoint.call_count == 1

    async def test_run(self):
        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", AsyncMock()),
            patch.object(Deliverer, "process_retries", AsyncMock()),
        ):
            Deliverer.running = False
            service = Deliverer("test", "test_topic", "test_retry_topic")
            await service.run()

        with (
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(side_effect=redis.exceptions.RedisError),
            ) as mock_redis,
            patch.object(Deliverer, "process_delivery", AsyncMock()),
            patch.object(Deliverer, "process_retries", AsyncMock()),
        ):
            Deliverer.running = False
            service = Deliverer("test", "test_topic", "test_retry_topic")
            await service.run()

    async def test_process_delivery_http(self):
        with (
            patch.object(
                test_module.aiohttp,
                "ClientSession",
                MagicMock(closed=False),
            ) as mock_session,
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_retries", AsyncMock()),
        ):
            mock_session.return_value = MagicMock(
                post=AsyncMock(return_value=MagicMock(status=200)),
                close=AsyncMock(),
            )
            Deliverer.running = PropertyMock(side_effect=[True, True, True, False])
            mock_redis.blpop = AsyncMock(
                side_effect=[
                    test_msg_a,
                    test_msg_c,
                    test_msg_d,
                ]
            )
            mock_redis.rpush = AsyncMock()
            mock_redis.zadd = AsyncMock()
            service = Deliverer("test", "test_topic", "test_retry_topic")
            service.redis = mock_redis
            await service.process_delivery()

        with (
            patch.object(
                aiohttp.ClientSession,
                "post",
                AsyncMock(return_value=MagicMock(status=200)),
            ),
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
            patch.object(Deliverer, "process_retries", AsyncMock()),
        ):
            Deliverer.running = PropertyMock(side_effect=[True, True, True, True, False])
            mock_redis.blpop = AsyncMock(
                side_effect=[
                    test_msg_a,
                    None,
                    test_msg_c,
                    test_msg_d,
                ]
            )
            mock_redis.rpush = AsyncMock()
            mock_redis.zadd = AsyncMock()
            service = Deliverer("test", "test_topic", "test_retry_topic")
            service.redis = mock_redis
            await service.process_delivery()

    async def test_process_delivery_msg_x(self):
        with (
            patch.object(
                aiohttp.ClientSession,
                "post",
                AsyncMock(
                    side_effect=[
                        aiohttp.ClientError,
                        asyncio.TimeoutError,
                        MagicMock(status=400),
                        MagicMock(status=200),
                    ]
                ),
            ),
            patch.object(
                redis.asyncio.RedisCluster,
                "from_url",
                MagicMock(),
            ) as mock_redis,
        ):
            Deliverer.running = PropertyMock(side_effect=[True, True, True, True, False])
            mock_redis.blpop = AsyncMock(
                side_effect=[
                    test_module.RedisError,
                    test_msg_a,
                    test_msg_d,
                    test_msg_err_b,
                    test_msg_err_c,
                ]
            )
            mock_redis.ping = AsyncMock()
            mock_redis.rpush = AsyncMock()
            mock_redis.zadd = AsyncMock(side_effect=[test_module.RedisError, None, None])
            service = Deliverer("test", "test_topic", "test_retry_topic")
            service.redis = mock_redis
            await service.process_delivery()

    async def test_process_retries_a(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            Deliverer.running = PropertyMock(side_effect=[True, True, True, False])
            mock_redis.zrangebyscore = AsyncMock(
                side_effect=[
                    test_msg_e,
                    test_msg_e,
                    None,
                ]
            )
            mock_redis.zrem = AsyncMock(return_value=1)
            mock_redis.rpush = AsyncMock()
            service = Deliverer("test", "test_topic", "test_retry_topic")
            service.retry_timedelay_s = 0.1
            service.redis = mock_redis
            await service.process_retries()

    async def test_process_retries_b(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            Deliverer.running = PropertyMock(side_effect=[True, False])
            mock_redis.zrangebyscore = AsyncMock(
                side_effect=[
                    test_module.RedisError,
                    [test_msg_e, test_msg_e, test_msg_e],
                ]
            )
            mock_redis.zrem = AsyncMock(
                side_effect=[0, test_module.RedisError, test_msg_e, 0]
            )
            mock_redis.rpush = AsyncMock(side_effect=[test_module.RedisError, None])
            service = Deliverer("test", "test_topic", "test_retry_topic")
            service.retry_timedelay_s = 0.1
            service.redis = mock_redis
            await service.process_retries()

    async def test_is_running(self):
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            sentinel = PropertyMock(return_value=True)
            Deliverer.running = sentinel
            service = Deliverer("test", "test_topic", "test_retry_topic")
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = True
            assert await service.is_running()
            sentinel = PropertyMock(return_value=False)
            Deliverer.running = sentinel
            service = Deliverer("test", "test_topic", "test_retry_topic")
            mock_redis = MagicMock(ping=AsyncMock())
            service.redis = mock_redis
            service.running = False
            assert not await service.is_running()
            sentinel = PropertyMock(return_value=True)
            Deliverer.running = sentinel
            service = Deliverer("test", "test_topic", "test_retry_topic")
            mock_redis = MagicMock(
                ping=AsyncMock(side_effect=redis.exceptions.RedisError)
            )
            service.redis = mock_redis
            service.running = True
            assert not await service.is_running()

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

    def test_outbound_payload_data_model(self):
        test_success_message = {
            "service": {"url": "http://echo:3002"},
            "payload": PAYLOAD_B64,
            "headers": {"Content-Type": "application/ssi-agent-wire"},
        }
        test_success_message = str.encode(json.dumps(test_success_message))
        assert test_module.OutboundPayload.from_bytes(test_success_message)
        test_fail_message = {
            "service": {"url": "http://echo:3002/fake/"},
            "payload": PAYLOAD_B64,
        }
        test_fail_message = str.encode(json.dumps(test_fail_message))
        assert test_module.OutboundPayload.from_bytes(test_fail_message)
