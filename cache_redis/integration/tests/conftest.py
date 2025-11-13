import os
import pytest_asyncio
from redis.asyncio import RedisCluster
from redis import asyncio as aioredis


@pytest_asyncio.fixture
async def redis_cluster_client():
    """Yield RedisCluster client."""
    subnet_prefix = os.environ.get("SUBNET_PREFIX", "172.28")
    redis = RedisCluster.from_url(
        url=f"redis://default:test1234@{subnet_prefix}.0.103:6382"
    )
    yield redis
    await redis.close()


@pytest_asyncio.fixture
async def redis_client():
    """Yield aioredis client."""
    redis = aioredis.from_url("redis://redis-host:6379/0")
    yield redis
    await redis.close()
