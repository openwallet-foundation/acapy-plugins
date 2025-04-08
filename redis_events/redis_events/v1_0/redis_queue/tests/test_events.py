import json
from copy import deepcopy
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.connections.models.connection_target import ConnectionTarget
from acapy_agent.core.event_bus import Event, EventWithMetadata, MockEventBus
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.transport.error import TransportError
from acapy_agent.transport.outbound.message import OutboundMessage
from aiohttp.test_utils import unused_port
from redis import asyncio as redis_asyncio
from redis import exceptions as redis_exceptions
from redis.asyncio import RedisCluster

from .. import events as test_module
from ..events import handle_event, on_shutdown, on_startup, process_event_payload, setup

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


class TestRedisEvents(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = unused_port()
        self.session = None
        self.profile = await create_test_profile(
            {
                "plugin_config": SETTINGS["plugin_config"],
            }
        )

    async def test_setup(self):
        context = MagicMock(
            settings=SETTINGS, inject=MagicMock(return_value=MockEventBus())
        )
        await setup(context)

    async def test_setup_x(self):
        context = MagicMock(settings=SETTINGS, inject=MagicMock(return_value=None))
        with self.assertRaises(ValueError):
            await setup(context)

    async def test_on_startup(self):
        test_event = Event("test_topic", {"rev_reg_id": "mock", "crids": ["mock"]})
        with patch.object(
            redis_asyncio.RedisCluster,
            "from_url",
            MagicMock(return_value=MagicMock(ping=AsyncMock())),
        ):
            await on_startup(self.profile, test_event)

    async def test_on_startup_x(self):
        test_event = Event("test_topic", {"rev_reg_id": "mock", "crids": ["mock"]})
        with patch.object(
            redis_asyncio.RedisCluster,
            "from_url",
            MagicMock(side_effect=redis_exceptions.RedisError),
        ):
            with self.assertRaises(TransportError):
                await on_startup(self.profile, test_event)

    async def test_on_shutddown(self):
        test_event = Event("test_topic", {"rev_reg_id": "mock", "crids": ["mock"]})
        await on_shutdown(self.profile, test_event)

    async def test_handle_event(self):
        self.profile = await create_test_profile(
            {
                "plugin_config": SETTINGS["plugin_config"],
                "emit_new_didcomm_mime_type": True,
                "wallet.id": "test_wallet_id",
            }
        )
        redis_cluster = MagicMock(RedisCluster, auto_spec=True)
        redis_cluster.rpush = AsyncMock()
        self.profile.context.injector.bind_instance(RedisCluster, redis_cluster)
        test_event_with_metadata = MagicMock(
            payload={
                "state": "test_state",
                "test": "test",
            },
            topic="acapy::basicmessage::received",
            metadata=MagicMock(
                pattern=MagicMock(pattern="acapy::basicmessage::received")
            ),
        )
        await handle_event(self.profile, test_event_with_metadata)
        real_event_with_metadata = EventWithMetadata(
            topic="acapy::outbound-message::queued_for_delivery",
            payload=OutboundMessage(
                connection_id="503a4f71-89f1-4bb2-b20d-e74c685ba325",
                enc_payload="",
                endpoint="",
                payload="""
                    {"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message", "@id": 
                    "99bf771c-93e4-4482-8ab9-45080927f67c", "content": "test", "sent_time": 
                    "2022-09-01T20:15:23.719131Z"}
                """,
                reply_session_id="",
                reply_thread_id="99bf771c-93e4-4482-8ab9-45080927f67c",
                reply_to_verkey="",
                reply_from_verkey="",
                target=ConnectionTarget(),
                target_list=[
                    ConnectionTarget(
                        did="6tb9bVM3SzFRMRxoWJTvp1",
                        endpoint="http://echo:3002",
                        label="test-runner",
                        recipient_keys=["4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ"],
                        routing_keys=[],
                        sender_key="4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ",
                    )
                ],
                to_session_only=False,
            ),
            metadata=MagicMock(
                pattern=MagicMock(pattern="acapy::outbound-message::queued_for_delivery")
            ),
        )
        await handle_event(self.profile, real_event_with_metadata)
        real_event_with_metadata = EventWithMetadata(
            topic="acapy::outbound-message::queued_for_delivery",
            payload=OutboundMessage(
                connection_id="503a4f71-89f1-4bb2-b20d-e74c685ba325",
                enc_payload="""
                    {"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message", "@id": 
                    "99bf771c-93e4-4482-8ab9-45080927f67c", "content": "test", "sent_time": 
                    "2022-09-01T20:15:23.719131Z"}
                """.encode("utf-8"),
                endpoint="",
                payload="{}",
                reply_session_id="",
                reply_thread_id="99bf771c-93e4-4482-8ab9-45080927f67c",
                reply_to_verkey="",
                reply_from_verkey="",
                target=ConnectionTarget(),
                target_list=[
                    ConnectionTarget(
                        did="6tb9bVM3SzFRMRxoWJTvp1",
                        endpoint="http://echo:3002",
                        label="test-runner",
                        recipient_keys=["4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ"],
                        routing_keys=[],
                        sender_key="4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ",
                    )
                ],
                to_session_only=False,
            ),
            metadata=MagicMock(
                pattern=MagicMock(pattern="acapy::outbound-message::queued_for_delivery")
            ),
        )
        await handle_event(self.profile, real_event_with_metadata)

    async def test_handle_event_deliver_webhook(self):
        test_settings = deepcopy(SETTINGS)
        test_settings["plugin_config"]["redis_queue"]["event"] = {"deliver_webhook": True}
        self.profile = await create_test_profile(
            {
                "plugin_config": test_settings["plugin_config"],
                "emit_new_didcomm_mime_type": True,
                "wallet.id": "test_wallet_id",
                "admin.webhook_urls": [
                    "http://0.0.0.0:9000#test_api_key_a",
                    "ws://0.0.0.0:9001",
                ],
            }
        )
        redis_cluster = MagicMock(RedisCluster, auto_spec=True)
        redis_cluster.rpush = AsyncMock()
        self.profile.context.injector.bind_instance(RedisCluster, redis_cluster)
        test_event_with_metadata = MagicMock(
            payload={
                "state": "test_state",
                "test": "test",
            },
            topic="acapy::basicmessage::received",
            metadata=MagicMock(
                pattern=MagicMock(pattern="acapy::basicmessage::received")
            ),
        )
        await handle_event(self.profile, test_event_with_metadata)

    async def test_handle_event_x(self):
        self.profile = await create_test_profile(
            {
                "plugin_config": SETTINGS["plugin_config"],
                "emit_new_didcomm_mime_type": False,
            }
        )
        with patch.object(
            test_module,
            "redis_setup",
            AsyncMock(
                return_value=MagicMock(
                    rpush=AsyncMock(side_effect=redis_exceptions.RedisError),
                )
            ),
        ):
            test_event_with_metadata = MagicMock(
                payload={
                    "state": "test_state",
                    "test": "test",
                },
                topic="acapy::basicmessage::received",
                metadata=MagicMock(
                    pattern=MagicMock(pattern="acapy::basicmessage::received")
                ),
            )
            await handle_event(self.profile, test_event_with_metadata)

    def test_process_event_payload(self):
        assert process_event_payload(
            {
                "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
                "@id": "bd9f3856-140c-4e9a-afc7-cc49936e4bc9",
                "content": "test2",
                "sent_time": "2022-09-01T20:15:59.671701Z",
            }
        )
        assert process_event_payload(
            '{"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message", "@id": "bd9f3856-140c-4e9a-afc7-cc49936e4bc9", "content": "test2", "sent_time": "2022-09-01T20:15:59.671701Z"}'
        )
