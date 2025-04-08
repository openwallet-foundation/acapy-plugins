import base64
import datetime
import json
import time
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import redis
from acapy_agent.transport.outbound.base import (
    ConnectionTarget,
    OutboundMessage,
    QueuedOutboundMessage,
)
from acapy_agent.transport.wire_format import BaseWireFormat
from acapy_agent.utils.testing import create_test_profile
from aiohttp.test_utils import unused_port

from .. import config as test_config
from .. import outbound as test_outbound
from .. import utils as test_util
from ..outbound import RedisOutboundQueue

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
                "mediator_mode": True,
            },
            "event": {
                "event_topic_maps": {
                    "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
                    "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
                    "^acapy::record::([^:])?": "acapy-record-$wallet_id",
                    "acapy::basicmessage::received": "acapy-basicmessage-received",
                }
            },
        }
    }
}

TEST_PAYLOAD_DICT = {
    "protected": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMCIsICJhbGciOiAiQXV0aGNyeXB0Ii"
    "wgInJlY2lwaWVudHMiOiBbeyJlbmNyeXB0ZWRfa2V5IjogIjVfSWF4dnA1a3FRVGZvTXpuZ3dlcDM0bG1aUUhCLTcyNVEx"
    "eVhmb2JnZWZMWlhRMXlweEIxemJveEswcmtuQXUiLCAiaGVhZGVyIjogeyJraWQiOiAiQkRnOFM2Z2t2bndEQjc1djVyb3"
    "lDRTFYclduNDJTcHg4ODVhVjdjeGFOSkwiLCAic2VuZGVyIjogIlFBRXRCV1d4MWZtd080LUJ2MmJXNFBTMDJyUGtveHZh"
    "b21HUkdiMWgyaEZsVUtHaGtIUS12N2hrOTJuWTR3Tnhwekd4T1cyVjFBZUdZbm9IcDNmTmtSRTdlT2MwUmpEeUhINVk0Ml"
    "F1Y1VJa1FFLUZreGZTV25TUDZESSIsICJpdiI6ICJfUDN6ZVNxYlFsMjJIRS1CZGhnTGxfMEd0TEF4ZzlhUiJ9fV19",
    "iv": "BomDTIjh4oP62Qjk",
    "ciphertext": "m3QU8IC4aK5rt691Ob1_khywx_DM5PPs_YN6MhfqbF579XjJi9ks4iaPf1rMIgxSFkXn-lP2hcM2TOqAtZz8S0rT6ff67"
    "5nLvlsfjm9exwvPfwm9C9VlK8wkcnJq3WxMvXngGnzl6-oK4qwCIwHAhMMCxoTdwsrKTzZ6lMd_1pNjmWGrQjgESuXK_y"
    "SUn78j5mT7vesNjOX0fiBqXhEmFzpIqDF-12GQWItepfINnhuJuPUpNkux7WoyQN5d-IBUJPkj7HEyS7SUA9Pw07wmFGC"
    "pX9eGWpxik0LgRICSSLcmabsTW6TtAUVYHrfoAdWNZEPZh3kTGF-dyzUP7BbJ465VsIWyfZfFdfWd9Z6SzZLUxOvYBQ8J"
    "vD8N1Z3iLqeQ92eWXbLitaOZuJ9SJXCW0p6ArEvJs-oLN_jmMJoLb_iT3ojqBVFwDhk4At1sglJcflE7tJCBOQ1AjOSGC"
    "dE5_fibIT8TFeNlPlp_ZNT-MinkXu1i9924xJN99utrbSmFBCn61iycm2oL-VnPBCTF3-mN6_Qx3-BkwFCs3QoToYdHiq"
    "0jZ2zKfmCwQOxqCCMfrZnFy8vyN59DN168iUt6EXxqd2xTBdxoFxUCiNw5lf3e8KX51xnxiQfaIJ1Ruiy5rwwfVekG9EJ"
    "g5S0vykYFsvyl7DGQn-qyj7EaQCoQYPdaa_jPPTfq-RodyZVfutL9fYyAW_TbJxRw1E1-r1tZnc2s4pCGy3l1meq5iQ5k"
    "H5ZXluRImVu5TMhKFrdwyzuFAMy5lHK3vHoU7goXUTHETMCgc-znesNALcOparey0dnxUM2mKG9MZRNJyTnsmsVc8i2Dk"
    "-jYEi24zWB4SeFXTSvPbtGjsgNaWwr_6FNrYgH0bP85v1XcMLF3pBYr4CJ_-P_uokF1XcTCm28jSNkNubG0EhFOHqT9fW"
    "1rJtYWH5M_mvic7yLgNUnrAcT-PhmUj8KyHSJjtmMXxKLznqUKu7nT6LlpBX0atim_bOsI28m9JMHzITj4VX_w1Ual8nH"
    "N2m5TSzB7ZxupeiRb27_H6NUhxWF8eIk5QOXnQk-5-ozxVw8ow9_C--xYz96YvkZj6lxbxpWi1nKu_0Vtl7DQVmpd34A4"
    "8bGMzDr7V2Ef9ClbDuraIhtWpEDcQGCnuJlEgCwy90Vz5EicGn586pEhiIroqj4FqkSSvoNeAM31XIxUXsN3Df8CWp0EO"
    "ONC_Il1VIoPvZilJwrrvgkv62rawqTiRra5TdBQEV1ZQrifzM79jtcRyf5JElppTcd-aFT-pkU50gGApLqf0eVA9RuVSb"
    "vW5k50x-U3wdOtEbmt2DKRT7qoZ9bamoCGXOY4ZRS88lZV66yt3ej781P49-TNHprUV9h6xb1tW68j4d38VuTQF74Om8y"
    "fvZXuyNLwjbCRNjSbRg1CCJKKFZUZSBbxvBPscFIABa_PZH-MlW2kyNTIQCfJfeYb6IziK7dno0RRkFsQfwy2UJPqptTe"
    "roJzFVeaREgMzsXwJvfSZVjgobl5PhfccTiT-PePpOmm_d_f5S6njIZUctgl1Ji0_krAGd4UfBmS5iOOu0VG5k-fZv-2p"
    "sryhekoU00PHXypJqR7MaHP5dkPK7cf4N4IBg13tQ8SDWY_OwFEOEEgJQj43dPZElNSMndOhB9hBLtD9tw2yQxMN_sgYI"
    "ggjC9epd_Drmo7RNOuNY0F1h4lenYhgzEQOhrET6K0SoIpkzxRRS9josxbUfIL5gbOa5efurn8OLOcLBxPqgyVNT7Whaq"
    "Bx6bc-h_ikjLeepB5xdmnBdajSULP9zBFfhx-qKEHaPKoaTQ7iXVMAx7NTi4I5Pb4oaFfOVnMK4ujqHNymKkecuxYhA5C"
    "YZQBDJURAds10CylsNOH837qUJ-_SbNN2b18dYKNep82c5NNzX48teqOXyY7KWtdiaxcmhgGTT8ozvqbX29HU8OKqSVnw"
    "viGPglV6Hn0xWDW9q0npnvYfWbHPQ9qWv4yOcqaPry7ehwh3rDoq8y0o7VgCd6-3_lwE7j41jjk6_dclZWOvTwibADoL3"
    "n-8Jep-bFF6oBgmLx9v-pG094VuspUhWIImoBDHx-oRK_X9HXn9RdkIJ7l-OQ_mON7f27xYBILcUcOGqkqZqemgUU-d0Q"
    "eq8ViVKJ0SSBkQJEOq_CyBCxHfql1W1X_Uu9rE7MEuRRQ-XRQFfTcf2igi72qCi_MwzKzM-Yd4hnOWc0O1PZcQApi01cS"
    "-9_eqNvKZ_2y3K1FQ4QUk-_3qaxvupjUwOsv2qUdArGoKewu1VgT5-8VkDLgpFp6c5MDXtMEpDLJKf7XVzhwFXbUlH7aG"
    "PEOauBQYp7eF8BICQzirAmbu9lw5FbbH6xCm-EimCTMdwjBdg",
    "tag": "SATpjQogpCts0mOGR-QAJA",
}
TEST_PAYLOAD_BYTES = (json.dumps(TEST_PAYLOAD_DICT)).encode()


class TestRedisOutbound(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = unused_port()
        self.session = None
        self.profile = await create_test_profile()

    async def test_init(self):
        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.ping = AsyncMock()
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        redis_outbound_inst = RedisOutboundQueue(
            root_profile=self.profile, wire_format=MagicMock()
        )

        assert redis_outbound_inst
        await redis_outbound_inst.start()
        await redis_outbound_inst.stop()

    async def test_init_no_bind_instance(self):
        RedisOutboundQueue.running = PropertyMock(side_effect=[True, True, True, False])
        with patch.object(
            redis.asyncio.RedisCluster,
            "from_url",
            MagicMock(
                return_value=MagicMock(
                    ping=AsyncMock(),
                )
            ),
        ) as mock_redis:
            redis_outbound_inst = RedisOutboundQueue(
                root_profile=self.profile, wire_format=MagicMock()
            )

            assert redis_outbound_inst
            await redis_outbound_inst.start()
            await redis_outbound_inst.stop()

    async def test_get_recip_keys_list_for_uid(self):
        redis = MagicMock(
            hget=AsyncMock(
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
                    ),
                    None,
                ]
            )
        )
        assert (await test_util.get_recip_keys_list_for_uid(redis, "test_uid_1")) == [
            "test_recip_key_1",
            "test_recip_key_2",
            "test_recip_key_3",
            "test_recip_key_5",
        ]
        assert (await test_util.get_recip_keys_list_for_uid(redis, "test_uid_2")) == []

    async def test_get_new_valid_uid(self):
        redis = MagicMock(
            get=AsyncMock(
                side_effect=[
                    None,
                    b"0",
                ]
            ),
            set=AsyncMock(),
            hkeys=AsyncMock(
                return_value=[
                    b"test_recip_key_a",
                    b"test_recip_key_b",
                    b"test_recip_key_c",
                ]
            ),
            ping=AsyncMock(),
        )
        assert (
            await test_util.get_new_valid_uid(redis, to_ignore_uid=b"test_recip_key_b")
        ) == b"test_recip_key_a"
        redis = MagicMock(
            get=AsyncMock(return_value=b"1"),
            set=AsyncMock(),
            hkeys=AsyncMock(
                return_value=[
                    b"test_recip_key_a",
                    b"test_recip_key_b",
                    b"test_recip_key_c",
                ]
            ),
            ping=AsyncMock(),
        )
        assert (
            await test_util.get_new_valid_uid(redis, to_ignore_uid=b"test_recip_key_b")
        ) == b"test_recip_key_c"
        redis = MagicMock(
            get=AsyncMock(return_value=b"3"),
            set=AsyncMock(),
            hkeys=AsyncMock(
                side_effect=[
                    [],
                    [
                        b"test_recip_key_a",
                        b"test_recip_key_b",
                        b"test_recip_key_c",
                    ],
                ]
            ),
            ping=AsyncMock(),
        )
        with patch.object(test_util.asyncio, "sleep", AsyncMock()):
            assert (
                await test_util.get_new_valid_uid(redis, b"test_recip_key_d")
            ) == b"test_recip_key_a"

    async def test_assign_recip_key_to_new_uid(self):
        redis = MagicMock(
            hset=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_new_valid_uid",
                AsyncMock(return_value=b"test_uid_a"),
            ),
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    return_value=base64.urlsafe_b64encode(
                        json.dumps(
                            [
                                "test_recip_key_a",
                                "test_recip_key_b",
                                "test_recip_key_c",
                            ]
                        ).encode("utf-8")
                    ).decode()
                ),
            ),
        ):
            assert (
                await test_util.assign_recip_key_to_new_uid(
                    redis, recip_key="test_recip_key_d"
                )
            ) == b"test_uid_a"

    async def test_reassign_recip_key_to_uid(self):
        redis = MagicMock(
            hget=AsyncMock(return_value=b"4"),
            hset=AsyncMock(),
            hdel=AsyncMock(),
            hincrby=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_new_valid_uid",
                AsyncMock(return_value=b"test_uid_a"),
            ),
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    side_effect=[
                        base64.urlsafe_b64encode(
                            json.dumps(
                                [
                                    "test_recip_key_a",
                                    "test_recip_key_b",
                                    "test_recip_key_c",
                                ]
                            ).encode("utf-8")
                        ).decode(),
                        base64.urlsafe_b64encode(
                            json.dumps(
                                [
                                    "test_recip_key_p",
                                    "test_recip_key_q",
                                    "test_recip_key_r",
                                ]
                            ).encode("utf-8")
                        ).decode(),
                    ]
                ),
            ),
        ):
            assert (
                await test_util.reassign_recip_key_to_uid(
                    redis, old_uid=b"test_uid_a", recip_key="test_recip_key_b"
                )
            ) == b"test_uid_a"
        # Missing recip_key from old_list and no old_pending_msg_count
        redis = MagicMock(
            hget=AsyncMock(return_value=None),
            hset=AsyncMock(),
            hdel=AsyncMock(),
            hincrby=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_new_valid_uid",
                AsyncMock(return_value=b"test_uid_a"),
            ),
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    side_effect=[
                        base64.urlsafe_b64encode(
                            json.dumps(
                                [
                                    "test_recip_key_a",
                                    "test_recip_key_b",
                                    "test_recip_key_c",
                                ]
                            ).encode("utf-8")
                        ).decode(),
                        base64.urlsafe_b64encode(
                            json.dumps(
                                [
                                    "test_recip_key_p",
                                    "test_recip_key_q",
                                    "test_recip_key_r",
                                ]
                            ).encode("utf-8")
                        ).decode(),
                    ]
                ),
            ),
        ):
            assert (
                await test_util.reassign_recip_key_to_uid(
                    redis, old_uid=b"test_uid_a", recip_key="test_recip_key_d"
                )
            ) == b"test_uid_a"

    def test_recipients_from_packed_message(self):
        assert (
            ",".join(test_util._recipients_from_packed_message(TEST_PAYLOAD_BYTES))
            == "BDg8S6gkvnwDB75v5royCE1XrWn42Spx885aV7cxaNJL"
        )

    def test_timedelta_utilities(self):
        curr_time = test_util.str_to_datetime(test_util.curr_datetime_to_str())
        time.sleep(1)
        test_util.get_timedelta_seconds(curr_time) >= 1

    async def test_handle_message_x(self):
        self.profile.settings["emit_new_didcomm_mime_type"] = True
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster,
            MagicMock(redis.asyncio.RedisCluster, auto_spec=True),
        )
        wire_format = BaseWireFormat()
        redis_outbound_inst = RedisOutboundQueue(self.profile)
        q_out_msg = QueuedOutboundMessage(
            profile=self.profile,
            message=OutboundMessage(payload="test-message"),
            target=ConnectionTarget(),
            transport_id="test-transport-id",
        )
        q_out_msg.payload = b'{"test":"test"}'
        with self.assertRaises(test_outbound.OutboundTransportError):
            await redis_outbound_inst.handle_message(
                self.profile,
                q_out_msg,
                None,
            )
        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.rpush = AsyncMock(side_effect=redis.exceptions.RedisError)
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        redis_outbound_inst = RedisOutboundQueue(
            root_profile=self.profile, wire_format=wire_format
        )
        await redis_outbound_inst.handle_message(
            self.profile,
            q_out_msg,
            "http://0.0.0.0:8000",
        )

    async def test_handle_message(self):
        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.rpush = AsyncMock(side_effect=redis.exceptions.RedisError)
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        with patch.object(
            test_outbound,
            "get_config",
            MagicMock(
                return_value=MagicMock(
                    outbound=MagicMock(
                        mediator_mode=False, acapy_outbound_topic="acapy_outbound"
                    )
                )
            ),
        ):
            redis_outbound_inst = RedisOutboundQueue(root_profile=self.profile)
            q_out_msg = QueuedOutboundMessage(
                profile=self.profile,
                message=OutboundMessage(payload="test-message"),
                target=ConnectionTarget(),
                transport_id="test-transport-id",
            )
            q_out_msg.payload = b'{"test":"test"}'
            await redis_outbound_inst.handle_message(
                self.profile,
                q_out_msg,
                "http://0.0.0.0:8000",
                {},
                "test_api_key",
            )

    async def test_handle_message_mediator(self):
        self.profile.settings["emit_new_didcomm_mime_type"] = True
        redis_cluster = MagicMock(redis.asyncio.RedisCluster, auto_spec=True)
        redis_cluster.rpush = AsyncMock(side_effect=redis.exceptions.RedisError)
        self.profile.context.injector.bind_instance(
            redis.asyncio.RedisCluster, redis_cluster
        )
        with (
            patch.object(
                test_outbound,
                "get_config",
                MagicMock(
                    return_value=MagicMock(
                        outbound=MagicMock(
                            mediator_mode=True, acapy_outbound_topic="acapy_inbound"
                        )
                    )
                ),
            ),
            patch.object(
                test_outbound,
                "process_payload_recip_key",
                AsyncMock(
                    return_value=(
                        "acapy_inbound_test_recip_key_a",
                        str.encode(json.dumps({"test": "test"})),
                    )
                ),
            ),
        ):
            redis_outbound_inst = RedisOutboundQueue(root_profile=self.profile)
            q_out_msg = QueuedOutboundMessage(
                profile=self.profile,
                message=OutboundMessage(payload="test-message"),
                target=ConnectionTarget(),
                transport_id="test-transport-id",
            )
            q_out_msg.payload = TEST_PAYLOAD_BYTES

            await redis_outbound_inst.handle_message(
                self.profile,
                q_out_msg,
                "http://0.0.0.0:8000",
                None,
                "test_api_key",
            )

    async def test_process_payload_recip_key_reassign_a(self):
        redis = MagicMock(
            rpush=AsyncMock(),
            hexists=AsyncMock(return_value=True),
            hget=AsyncMock(
                side_effect=[
                    b"test_uid_a",
                    (
                        (
                            datetime.datetime.now() - datetime.timedelta(seconds=16)
                        ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    ).encode(),
                    b"1",
                    None,
                    b"0",
                ]
            ),
            hincrby=AsyncMock(),
            hdel=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    side_effect=[
                        [
                            "BDg8S6gkvnwDB75v5royCE1XrWn42Spx885aV7cxaNJL",
                            "test_recip_key_b",
                            "test_recip_key_c",
                        ],
                        [],
                    ]
                ),
            ),
            patch.object(
                test_util,
                "reassign_recip_key_to_uid",
                AsyncMock(
                    side_effect=[
                        b"test_uid_p",
                        b"test_uid_q",
                        b"test_uid_r",
                    ]
                ),
            ),
        ):
            await test_util.process_payload_recip_key(
                redis, TEST_PAYLOAD_BYTES, "acapy_inbound"
            )

    async def test_process_payload_recip_key_reassign_b(self):
        redis = MagicMock(
            rpush=AsyncMock(),
            hexists=AsyncMock(return_value=True),
            hget=AsyncMock(
                side_effect=[
                    b"test_uid_a",
                    (
                        (
                            datetime.datetime.now() - datetime.timedelta(seconds=16)
                        ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    ).encode(),
                    b"1",
                    None,
                    b"0",
                ]
            ),
            hincrby=AsyncMock(),
            hdel=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    side_effect=[
                        [
                            "test_recip_key_a",
                            "BDg8S6gkvnwDB75v5royCE1XrWn42Spx885aV7cxaNJL",
                            "test_recip_key_c",
                        ],
                        [],
                    ]
                ),
            ),
            patch.object(
                test_util,
                "reassign_recip_key_to_uid",
                AsyncMock(
                    side_effect=[
                        b"test_uid_p",
                        b"test_uid_q",
                        b"test_uid_a",
                    ]
                ),
            ),
        ):
            await test_util.process_payload_recip_key(
                redis, TEST_PAYLOAD_BYTES, "acapy_inbound"
            )

    async def test_process_payload_recip_key_no_last_access(self):
        redis = MagicMock(
            rpush=AsyncMock(),
            hexists=AsyncMock(return_value=True),
            hget=AsyncMock(
                side_effect=[
                    b"test_uid_a",
                    None,
                    None,
                    b"1",
                    b"0",
                ]
            ),
            hincrby=AsyncMock(),
            hdel=AsyncMock(),
        )
        with (
            patch.object(
                test_util,
                "get_recip_keys_list_for_uid",
                AsyncMock(
                    side_effect=[
                        [
                            "test_recip_key_a",
                            "test_recip_key_b",
                            "BDg8S6gkvnwDB75v5royCE1XrWn42Spx885aV7cxaNJL",
                        ],
                        ["test_recip_key_d"],
                    ]
                ),
            ),
            patch.object(
                test_util,
                "reassign_recip_key_to_uid",
                AsyncMock(
                    side_effect=[
                        b"test_uid_p",
                        b"test_uid_p",
                        b"test_uid_a",
                    ]
                ),
            ),
        ):
            await test_util.process_payload_recip_key(
                redis, TEST_PAYLOAD_BYTES, "acapy_inbound"
            )

    async def test_process_payload_recip_key_assign_new_uid(self):
        redis = MagicMock(
            rpush=AsyncMock(),
            hexists=AsyncMock(return_value=False),
            hget=AsyncMock(
                return_value=(
                    (datetime.datetime.now() - datetime.timedelta(seconds=5)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                ).encode(),
            ),
            hincrby=AsyncMock(),
            hdel=AsyncMock(),
        )
        with patch.object(
            test_util,
            "assign_recip_key_to_new_uid",
            AsyncMock(return_value=b"test_uid_a"),
        ):
            await test_util.process_payload_recip_key(
                redis, TEST_PAYLOAD_BYTES, "acapy_inbound"
            )

    def test_get_config(self):
        test_redis_config = test_config.get_config(SETTINGS)
        assert isinstance(test_redis_config.event, test_config.EventConfig)
        assert isinstance(test_redis_config.inbound, test_config.InboundConfig)
        assert isinstance(test_redis_config.outbound, test_config.OutboundConfig)
        assert isinstance(test_redis_config.connection, test_config.ConnectionConfig)

        assert test_redis_config.event.event_topic_maps == {
            "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
            "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
            "^acapy::record::([^:])?": "acapy-record-$wallet_id",
            "acapy::basicmessage::received": "acapy-basicmessage-received",
        }
        assert test_redis_config.inbound.acapy_inbound_topic == "acapy_inbound"
        assert (
            test_redis_config.inbound.acapy_direct_resp_topic
            == "acapy_inbound_direct_resp"
        )
        assert test_redis_config.outbound.acapy_outbound_topic == "acapy_outbound"
        assert test_redis_config.outbound.mediator_mode is True
        assert test_redis_config.connection.connection_url == "test"
