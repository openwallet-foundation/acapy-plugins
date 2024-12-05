import base64
import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import redis
from acapy_agent.messaging.error import MessageParseError
from acapy_agent.utils.testing import create_test_profile
from aiohttp.test_utils import unused_port

from .. import inbound as test_inbound
from ..inbound import RedisInboundTransport

SETTINGS = {
    "plugin_config": {
        "redis_queue": {
            "connection": {"connection_url": "test"},
            "inbound": {
                "acapy_inbound_topic": "acapy_inbound",
                "acapy_direct_resp_topic": "acapy_inbound_direct_resp",
            },
            "outbound": {
                "acapy_outbound_topic": "acapy_outbound",
                "mediator_mode": False,
            },
        }
    }
}

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

TEST_INBOUND_MSG_DIRECT_RESPONSE = str.encode(
    json.dumps(
        {
            "payload": PAYLOAD_B64,
            "txn_id": "test1234",
            "transport_type": "http",
        }
    )
)

TEST_INBOUND_MSG_A = str.encode(
    json.dumps(
        {
            "payload": PAYLOAD_B64,
        }
    )
)

TEST_INBOUND_MSG_B = str.encode(
    json.dumps(
        {
            "payload": PAYLOAD_B64,
            "transport_type": "http",
        }
    )
)

TEST_INBOUND_MSG_C = str.encode(
    json.dumps(
        {
            "payload": PAYLOAD_B64,
            "transport_type": "ws",
        }
    )
)

TEST_INBOUND_INVALID = b"""{
    "payload" "==",
    "transport_type": "ws",
}"""


class TestRedisInbound(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = unused_port()
        self.session = None
        self.profile = await create_test_profile()

    async def test_init(self):
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster,
            MagicMock(redis.asyncio.RedisCluster, auto_spec=True),
        )
        RedisInboundTransport.running = PropertyMock(
            side_effect=[True, True, True, False]
        )
        redis_inbound_inst = RedisInboundTransport(
            "0.0.0.0",
            self.port,
            AsyncMock(
                return_value=MagicMock(
                    receive=AsyncMock(),
                    wait_response=AsyncMock(
                        side_effect=[
                            b"test_response_1",
                            "test_response_2",
                            MessageParseError,
                        ]
                    ),
                    profile=MagicMock(settings={"emit_new_didcomm_mime_type": True}),
                )
            ),
            root_profile=self.profile,
        )

        assert redis_inbound_inst

    async def test_init_no_bind_instance(self):
        RedisInboundTransport.running = PropertyMock(
            side_effect=[True, True, True, False]
        )
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(),
        ) as mock_redis:
            mock_redis = MagicMock(ping=AsyncMock())
            redis_inbound_inst = RedisInboundTransport(
                "0.0.0.0",
                self.port,
                AsyncMock(
                    return_value=MagicMock(
                        receive=AsyncMock(),
                        wait_response=AsyncMock(
                            side_effect=[
                                b"test_response_1",
                                "test_response_2",
                                MessageParseError,
                            ]
                        ),
                        profile=MagicMock(settings={"emit_new_didcomm_mime_type": True}),
                    )
                ),
                root_profile=self.profile,
            )

            assert redis_inbound_inst

    async def test_start(self):
        self.profile.settings["emit_new_didcomm_mime_type"] = False

        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.hset = AsyncMock()
        redis_cluster.ping = AsyncMock()
        redis_cluster.hget = AsyncMock(
            side_effect=[
                base64.urlsafe_b64encode(
                    json.dumps(
                        [
                            "test_recip_key_1",
                            "test_recip_key_2",
                            "test_recip_key_3",
                            "test_recip_key_5",
                        ]
                    ).encode("utf-8")
                ).decode(),
                b"1",
                b"2",
                b"1",
                base64.urlsafe_b64encode(
                    json.dumps(
                        [
                            "test_recip_key_1",
                            "test_recip_key_2",
                            "test_recip_key_4",
                            "test_recip_key_3",
                            "test_recip_key_5",
                        ]
                    ).encode("utf-8")
                ).decode(),
                b"1",
                b"1",
                b"2",
                b"3",
                None,
            ]
        )
        redis_cluster.blpop = AsyncMock(
            side_effect=[
                (None, TEST_INBOUND_MSG_DIRECT_RESPONSE),
                (None, TEST_INBOUND_MSG_A),
                (None, TEST_INBOUND_MSG_B),
                (None, TEST_INBOUND_INVALID),
                (None, TEST_INBOUND_MSG_DIRECT_RESPONSE),
                None,
                (None, TEST_INBOUND_MSG_B),
                (None, TEST_INBOUND_MSG_C),
                (None, TEST_INBOUND_MSG_DIRECT_RESPONSE),
            ]
        )
        redis_cluster.rpush = AsyncMock(side_effect=[redis.exceptions.RedisError, None])

        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        with patch.object(test_inbound.asyncio, "sleep", AsyncMock()):
            RedisInboundTransport.running = PropertyMock(
                side_effect=[
                    True,
                    True,
                    True,
                    False,
                ]
            )
            redis_inbound_inst = RedisInboundTransport(
                "0.0.0.0",
                self.port,
                AsyncMock(
                    return_value=MagicMock(
                        receive=AsyncMock(),
                        wait_response=AsyncMock(
                            side_effect=[
                                b"test_response_1",
                                "test_response_2",
                                MessageParseError,
                            ]
                        ),
                        profile=self.profile,
                    )
                ),
                root_profile=self.profile,
            )

            await redis_inbound_inst.start()
            await redis_inbound_inst.stop()

    async def test_start_x(self):
        self.profile.settings["emit_new_didcomm_mime_type"] = True

        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.hset = AsyncMock()
        redis_cluster.ping = AsyncMock()
        redis_cluster.hget = AsyncMock(
            side_effect=[
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                base64.urlsafe_b64encode(
                    json.dumps(
                        [
                            "test_recip_key_1",
                            "test_recip_key_2",
                            "test_recip_key_3",
                        ]
                    ).encode("utf-8")
                ).decode(),
                b"1",
            ]
        )
        redis_cluster.blpop = AsyncMock(
            side_effect=[
                (None, b'{"test": "test"}'),
                (None, TEST_INBOUND_MSG_DIRECT_RESPONSE),
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
                redis.exceptions.RedisError,
            ]
        )
        redis_cluster.rpush = AsyncMock(side_effect=[redis.exceptions.RedisError, None])
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        with patch.object(test_inbound.asyncio, "sleep", AsyncMock()):
            RedisInboundTransport.running = PropertyMock(
                side_effect=[
                    True,
                    True,
                    True,
                    True,
                    True,
                    True,
                    True,
                    False,
                ]
            )
            redis_inbound_inst = RedisInboundTransport(
                "0.0.0.0",
                self.port,
                AsyncMock(
                    return_value=MagicMock(
                        receive=AsyncMock(),
                        wait_response=AsyncMock(
                            side_effect=[
                                b"test_response_1",
                            ]
                        ),
                        profile=self.profile,
                    )
                ),
                root_profile=self.profile,
            )
            with self.assertRaises(test_inbound.InboundTransportError):
                await redis_inbound_inst.start()
                await redis_inbound_inst.stop()
