"""Testing basic redis stuff."""

import pytest


@pytest.mark.asyncio
async def test_round_trip(redis):
    """Test that we can get to and from Redis."""

    await redis.rpush(
        "test-topic",
        b"test-payload",
    )
    msg = await redis.blpop("test-topic", 0.2)
    assert msg
    assert msg[1] == b"test-payload"
