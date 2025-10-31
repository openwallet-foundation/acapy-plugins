from redis import asyncio as aioredis
import json
import logging

from acapy_agent.cache.base import BaseCache, CacheKeyLock
from acapy_agent.core.profile import Profile
from acapy_agent.core.error import BaseError
from redis.asyncio import RedisCluster
from redis.exceptions import RedisError, RedisClusterException
from typing import Any, Sequence, Text, Union

LOGGER = logging.getLogger(__name__)


class RedisBaseCache(BaseCache):
    """Redis Base Cache."""

    config_key = "redis_cache"
    prefix = "ACA-Py"

    def __init__(self, root_profile: Profile) -> None:
        """Initialize the cache instance."""
        LOGGER.debug("Initializing Redis Base Cache")
        super().__init__()
        # looks like { "key": { "expires": <epoch timestamp>, "value": <val> } }
        """Set initial state."""
        self.username = None
        self.password = None
        self.ca_cert = None
        self.root_profile = root_profile

        # Get the connection string
        try:
            plugin_config = self.root_profile.settings["plugin_config"] or {}
            config = plugin_config[self.config_key]
            self.connection = config["connection"]
        except KeyError as error:
            raise RedisCacheConfigurationError(
                "Configuration missing for redis queue"
            ) from error

        # Get the credentials for the redis server (for those with ACL enabled)
        try:
            credentials = config["credentials"]
            self.username = credentials["username"]
            self.password = credentials["password"]
        except KeyError:
            pass

        # Get the connection string
        try:
            self.max_connections = int(config["max_connections"])
        except KeyError:
            self.max_connections = 50
        LOGGER.debug(f"Max Redis Cache Pool connections set to: {self.max_connections}")

        # Get the SSL CA Cert information (special redis SSL implementations only)
        try:
            lssl = config["ssl"]
            self.ca_cert = lssl["cacerts"]
        except KeyError:
            pass

        # Get the prefix to seperate out ACA-Py instances
        self.prefix = config.get("prefix", "ACA-Py")
        self.prefix = "ACA-Py" if len(self.prefix) < 1 else self.prefix

        # Setup the aioredis instance
        self.pool = aioredis.ConnectionPool.from_url(
            self.connection,
            max_connections=self.max_connections,
            username=self.username,
            password=self.password,
            # ssl_ca_certs=self.ca_cert,
        )
        self.redis = aioredis.Redis(connection_pool=self.pool)

    async def check_for_redis_cluster(self):
        """
        Check if connection corresponds to a cluster node. If so,
        reassign redis to redis.asyncio.RedisCluster client.

        """
        cluster_info = await self.redis.info("cluster")
        if "cluster_enabled" in cluster_info and cluster_info["cluster_enabled"] == 1:
            self.redis = self.root_profile.inject_or(RedisCluster)
            if not self.redis:
                self.redis = RedisCluster.from_url(
                    self.connection,
                    max_connections=self.max_connections,
                    username=self.username,
                    password=self.password,
                )
                # Binds RedisCluster cluster instance, so that it is
                # accessible to redis_queue plugin.
                LOGGER.info(
                    "Found redis connection string correspond to a cluster node,"
                    " reassigning redis to redis.asyncio.RedisCluster client."
                )
                self.root_profile.context.injector.bind_instance(
                    RedisCluster, self.redis
                )
                await self.redis.ping(target_nodes=RedisCluster.PRIMARIES)
            else:
                LOGGER.info("Using an existing provided instance of RedisCluster.")

    def _getKey(self, key: Text) -> Text:
        return f"{self.prefix}:{key}"

    async def get(self, key: Text):
        """
        Get an item from the cache.

        Args:
            key: the key to retrieve an item for

        Returns:
            The record found or `None`

        """
        response = await self.redis.get(self._getKey(key))
        if response is not None:
            response = json.loads(response)
        return response

    async def set(self, keys: Union[Text, Sequence[Text]], value: Any, ttl: int = None):
        """
        Add an item to the cache with an optional ttl.

        Args:
            keys: the key or keys for which to set an item
            value: the value to store in the cache
            ttl: number of second that the record should persist

        """
        LOGGER.debug("set:%s value:%s ttl:%d", keys, value, ttl)
        try:
            for key in [keys] if isinstance(keys, Text) else keys:
                # self._cache[key] = {"expires": expires_ts, "value": value}
                await self.redis.set(self._getKey(key), json.dumps(value), ex=ttl)
        except (
            aioredis.RedisError,
            RedisClusterException,
            RedisError,
        ) as error:
            raise RedisCacheSetKeyValueError(
                "Unexpected redis client exception"
            ) from error

    async def clear(self, key: Text):
        """
        Remove an item from the cache, if present.

        Args:
            key: the key to remove

        """
        await self.redis.delete(self._getKey(key))

    async def flush(self):
        """Remove all items from the cache."""
        await self.redis.delete(self._getKey("*"))

    # Currently causes ACA-Py to freeze.
    # TODO: Figure out why this freezes ACA-Py and fix it
    # def acquire(self, key: Text):
    #     """Acquire a lock on a given cache key."""
    #     # result = self.redis.lock(self._getKey(key))
    #     result = RedisLock(self, self._getKey(key))
    #     first = self._key_locks.setdefault(key, result)
    #     return result
    #     if first is not result:
    #         result.parent = first
    #     return result

    # def release(self, key: Text):
    #     """Release the lock on a given cache key."""
    #     if key in self._key_locks:
    #         del self._key_locks[key]


class RedisLock(CacheKeyLock):
    def __init__(self, cache: BaseCache, key: Text):
        super().__init__(cache, key)
        self.redis_lock = cache.redis.lock(key, timeout=1)

    async def __aenter__(self):
        await super().__aenter__()
        await self.redis_lock.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.redis_lock.__aexit__(exc_type, exc_val, exc_tb)
        return await super().__aexit__(exc_type, exc_val, exc_tb)


class RedisCacheConfigurationError(BaseError):
    """An error with the redis cache configuration."""

    def __init__(self, message):
        """Initialize the exception instance."""
        super().__init__(message)


class RedisCacheSetKeyValueError(BaseError):
    """An error with the redis cache set key."""

    def __init__(self, message):
        """Initialize the exception instance."""
        super().__init__(message)
