"""Basic Message Tests"""

import json
import time

import pytest

from . import ALICE, FABER, RELAY, Agent


@pytest.fixture(scope="session")
def faber():
    """faber agent fixture."""
    yield Agent(FABER)


@pytest.fixture(scope="session")
def alice():
    """alice agent fixture."""
    yield Agent(ALICE)


@pytest.fixture(scope="session")
def relay():
    """alice agent fixture."""
    yield Agent(RELAY)


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


@pytest.fixture(scope="session", autouse=True)
def established_connection(faber, alice):
    """Established connection filter."""
    invite = alice.create_invitation(
        {
            "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
        },
        auto_accept="true",
    )["invitation"]
    resp = faber.receive_invite(invite, auto_accept="true")
    yield resp["connection_id"]


@pytest.mark.asyncio
async def test_base_redis_keys_are_set(redis):
    time.sleep(1)
    assert await redis.lrange("acapy-record-base", 0, -1) != []
    assert await redis.lrange("acapy-record-with-state-base", 0, -1) != []


@pytest.mark.asyncio
async def test_outbound_queue_removes_messages_from_queue_and_deliver_sends_them(
    faber: Agent, established_connection: str, redis
):
    faber.send_message(established_connection, "Hello Alice")
    faber.send_message(established_connection, "Another Alice")
    messages = faber.retrieve_basicmessages()["results"]
    assert "Hello Alice" in (msg["content"] for msg in messages)
    assert "Another Alice" in (msg["content"] for msg in messages)


@pytest.mark.asyncio
async def test_deliverer_pulls_messages_from_queue_and_sends_them(
    faber: Agent, established_connection: str, redis
):
    test_msg = "eyJjb250ZW50IjogInRlc3QtbXNnIn0="  # {"content": "test-msg"}
    outbound_msg = {
        "service": {
            "url": f"{faber.url}/connections/{established_connection}/send-message"
        },
        "payload": test_msg,
    }
    await redis.rpush(
        "acapy_outbound",
        str.encode(json.dumps(outbound_msg)),
    )

    time.sleep(5)
    messages = faber.retrieve_basicmessages()["results"]
    matching_msgs = [msg for msg in messages if msg["content"] == "test-msg"]
    assert matching_msgs.__len__() == 2  # 1 for sent, 1 for received
    assert await redis.lrange("acapy_outbound", 0, -1) == []


@pytest.mark.asyncio
async def test_relay_has_keys_in_recip_key_uid_map(redis, relay: Agent):
    time.sleep(1)
    recip_keys = await redis.hgetall("recip_key_uid_map")
    assert recip_keys
    msg_count = await redis.hgetall("uid_recip_key_pending_msg_count")
    assert msg_count


@pytest.mark.asyncio
async def test_deliverer_retry_on_failure(
    faber: Agent,
    established_connection: str,
    redis,
):
    outbound_msg = {
        "service": {"url": "http://alice:3002/fake/"},
        "payload": PAYLOAD_B64,
    }
    # produce a outbound message with bad endpoint
    await redis.rpush(
        "acapy_outbound",
        str.encode(json.dumps(outbound_msg)),
    )
    # assume failure code 400, delay queue, and failure code 400 ...
    time.sleep(1)
    msg = await redis.blpop("acapy_outbound", 10)
    assert msg
    # check for manual commit of previous message by handling a new message
    faber.send_message(established_connection, "test-failed-msg")
    msg_received = False
    retry_pop_count = 0
    while not msg_received:
        msg = await redis.blpop("acapy_outbound", 10)
        if not msg:
            if retry_pop_count > 3:
                raise Exception("blpop call failed to retrieve message")
            retry_pop_count = retry_pop_count + 1
            time.sleep(1)
        msg_received = True

    assert "test-failed-msg" in (
        msg["content"] for msg in faber.retrieve_basicmessages()["results"]
    )
