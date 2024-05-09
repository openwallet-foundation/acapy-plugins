"""Common fixtures for testing."""

import pytest
from redis.asyncio import RedisCluster


@pytest.fixture
def redis():
    redis = RedisCluster.from_url(url="redis://default:test1234@172.28.0.103:6379")
    yield redis
