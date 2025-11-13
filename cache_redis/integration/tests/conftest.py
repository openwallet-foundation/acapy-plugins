import pytest
import pytest_asyncio
from redis.asyncio import RedisCluster
from redis import asyncio as aioredis

@pytest_asyncio.fixture
async def redis_cluster_client():
    """Yield RedisCluster client."""
    redis = RedisCluster.from_url(url="redis://default:test1234@172.28.0.103:6382")
    yield redis
    await redis.close()
    
@pytest_asyncio.fixture
async def redis_client():
    """Yield aioredis client."""
    redis = aioredis.from_url("redis://redis-host:6379/0")
    yield redis
    await redis.close()