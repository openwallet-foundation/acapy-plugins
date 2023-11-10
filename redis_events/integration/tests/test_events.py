"""Basic Message Tests"""
import json
import time

import pytest

from . import FABER, ALICE, RELAY, Agent, post


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

PAYLOAD_JSON = {
    "protected": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMCIsICJhbGciOiAiQXV0aGNyeXB0IiwgInJlY2lwaWVudHMiOiBbeyJlbmNyeXB0ZWRfa2V5IjogIjFjZ3l0Qm13M3ExaGdiVzBJbjNtSG82WWhLT2tpRzVEeThrRjJIWjYxcTJvWWM3bmtuSzlOSUc2SEhlU2NoeWEiLCAiaGVhZGVyIjogeyJraWQiOiAiNERCSjRacDg1MWdqek50Sm1tb0U5N1dxVnJXTjM2eVpSYUdpZjRBR3J4d1EiLCAic2VuZGVyIjogIjNWcHlScUFZTWsyNk5Fc0QzNmNfZ2g0VHk0ZjgwMGxDRGEwM1llRW5mRXBmV2hJLWdzZEctVGRkMWVNaDlZSXo3NHRFSzJsR1VaTXpfNGt1d0JTUko0TF9hd1RKQVVVd2tTVnhrMzRnUVVfNWdrd1RkOEY1TkFlSU5QVSIsICJpdiI6ICJqVVJCQmNiT3g3NkNsVl8xazhRM29rUnJtRGQ1a3BpQiJ9fV19",
    "iv": "MWgGuQ4_ZogqURTn",
    "ciphertext": "UMLaP9Mwd_p8TumgpqVVAfSIfWsX7kIV-DxFw_TtSCjVu5SlnQbkdMRKwurdb5vgzCKT5ArlUtXAL2mlIIiPjRc5fK8KsMwKGEzi2pKkvlC7Q3QtJY19ZeSJ9X0iT9lNjcD3nJKJ5o9dJ8UXfi5O4dKZ-leW-j8ysLASI8uxFXUShRle7-7nnGfFgFVAF3ZYZj6TWQBkvGRROzO30LsDXpsjSj1f_wNzEgqNjO0DYzdJkIA6mACP",
    "tag": "eAeQbjI-Vjd7maqgS4IFNQ"
}


@pytest.fixture(scope="session", autouse=True)
def established_connection(faber, alice):
    """Established connection filter."""
    invite = alice.create_invitation(auto_accept="true")["invitation"]
    resp = faber.receive_invite(invite, auto_accept="true")
    yield resp["connection_id"]


@pytest.mark.asyncio
async def test_base_redis_keys_are_set(redis):
    time.sleep(1)
    assert await redis.lrange("acapy-record-base", 0, -1) != []
    assert await redis.lrange("acapy-record-with-state-base", 0, -1) != []


@pytest.mark.asyncio
async def test_outbound_queue_removes_messages_from_queue(faber: Agent, established_connection: str, redis):
    faber.send_message(established_connection, "Hello Alice")
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
    assert "Hello Alice" in (msg['content']
                             for msg in faber.retrieve_basicmessages()['results'])


@pytest.mark.asyncio
async def test_deliverer_pulls_messages_from_queue_and_sends_them(
    faber: Agent,
    established_connection: str,
    redis
):
    test_msg = "eyJjb250ZW50IjogInRlc3QtbXNnIn0="  # {"content": "test-msg"}
    outbound_msg = {
        "service": {"url": f"{faber.url}/connections/{established_connection}/send-message"},
        "payload": test_msg,
    }
    await redis.rpush(
        "acapy_outbound",
        str.encode(json.dumps(outbound_msg)),
    )

    time.sleep(5)
    messages = faber.retrieve_basicmessages()['results']
    matching_msgs = [
        msg for msg in messages if msg['content'] == "test-msg"]
    assert matching_msgs.__len__() == 1
    assert await redis.lrange("acapy_outbound", 0, -1) == []


@pytest.mark.asyncio
async def test_relay_sets_redis_keys_for_queue(redis, relay: Agent):
    post(relay.url, "/", json=PAYLOAD_JSON)
    time.sleep(1)
    uid = await redis.hget("recip_key_uid_map", "4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ")
    assert uid

    msg_count = await redis.hget("uid_recip_key_pending_msg_count", uid.decode() + "_4DBJ4Zp851gjzNtJmmoE97WqVrWN36yZRaGif4AGrxwQ")
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
    faber.send_message(established_connection, 'test-failed-msg')
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

    assert "test-failed-msg" in (msg['content']
                                 for msg in faber.retrieve_basicmessages()['results'])
