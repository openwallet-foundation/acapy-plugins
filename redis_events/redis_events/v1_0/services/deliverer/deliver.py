"""Redis Outbound Delivery Service."""

import asyncio
import base64
import json
import logging
import signal
from contextlib import suppress
from os import getenv
from time import time

import aiohttp
from redis.asyncio import RedisCluster
from redis.exceptions import RedisClusterException, RedisError

from redis_events.v1_0.status_endpoint.status_endpoints import (
    start_status_endpoints_server,
)

from . import OutboundPayload

logging.basicConfig(
    format="%(asctime)s | %(levelname)s: %(message)s",
    level=logging.INFO,
)


class Deliverer:
    """Outbound http delivery handler."""

    running = False
    ready = False

    def __init__(self, connection_url: str, topic: str, retry_topic: str):
        """Initialize RedisHandler."""
        self.retry_interval = 5
        self.retry_backoff = 0.25
        self.outbound_topic = topic
        self.retry_topic = retry_topic
        self.redis = None
        self.retry_timedelay_s = 1
        self.connection_url = connection_url

    async def run(self):
        """Run the service."""
        try:
            self.redis = RedisCluster.from_url(url=self.connection_url)
            self.ready = True
            self.running = True
            await asyncio.gather(self.process_delivery(), self.process_retries())
        except (RedisError, RedisClusterException) as err:
            self.ready = False
            self.running = False
            logging.error(f"Unable to connect to Redis, {err}")

    async def is_running(self) -> bool:
        """Check if delivery service agent is running properly."""
        try:
            await self.redis.ping(target_nodes=RedisCluster.PRIMARIES)
            if self.running:
                return True
            else:
                return False
        except (RedisError, RedisClusterException):
            return False

    async def process_delivery(self):
        """Process delivery."""
        client_session = None
        try:
            while self.running:
                msg_received = False
                while not msg_received:
                    try:
                        msg = await self.redis.blpop(self.outbound_topic, 0.2)
                        msg_received = True
                    except (RedisError, RedisClusterException) as err:
                        await asyncio.sleep(1)
                        logging.exception(
                            f"Unexpected redis client exception (blpop): {err}"
                        )
                if not msg:
                    await asyncio.sleep(0.2)
                    continue
                msg = OutboundPayload.from_bytes(msg[1])
                headers = msg.headers
                endpoint = msg.service.url
                payload = msg.payload
                endpoint_scheme = msg.endpoint_scheme
                if endpoint_scheme == "http" or endpoint_scheme == "https":
                    session_args = {
                        "cookie_jar": aiohttp.DummyCookieJar(),
                        "connector": aiohttp.TCPConnector(limit=200, limit_per_host=50),
                        "trust_env": True,
                    }
                    client_session = aiohttp.ClientSession(**session_args)
                    failed = False
                    try:
                        response = await client_session.post(
                            endpoint, data=payload, headers=headers, timeout=10
                        )
                        if response.status < 200 or response.status >= 300:
                            logging.error(
                                f"Invalid response : {response.status} - "
                                f"{response.reason}"
                            )
                            failed = True
                    except aiohttp.ClientError:
                        failed = True
                    except asyncio.TimeoutError:
                        failed = True
                    finally:
                        await client_session.close()
                    if failed:
                        logging.exception(f"Delivery failed for {endpoint}")
                        retries = msg.retries or 0
                        if retries < 5:
                            await self.add_retry(
                                {
                                    "service": {"url": endpoint},
                                    "headers": headers,
                                    "payload": base64.urlsafe_b64encode(payload).decode(),
                                    "retries": retries + 1,
                                }
                            )
                        else:
                            logging.error(f"Exceeded max retries for {str(endpoint)}")
                    else:
                        logging.info(f"Message dispatched to {endpoint}")
                elif endpoint_scheme == "ws":
                    session_args = {
                        "cookie_jar": aiohttp.DummyCookieJar(),
                        "trust_env": True,
                    }
                    client_session = aiohttp.ClientSession(**session_args)
                    async with client_session.ws_connect(endpoint, headers=headers) as ws:
                        if isinstance(payload, bytes):
                            await ws.send_bytes(payload)
                        else:
                            await ws.send_str(payload)
                        logging.info(f"WS message dispatched to {endpoint}")
                else:
                    logging.error(f"Unsupported scheme: {endpoint_scheme}")
        finally:
            if client_session and not client_session.closed:
                await client_session.close()

    async def add_retry(self, message: dict):
        """Add undelivered message for future retries."""
        zadd_sent = False
        while not zadd_sent:
            try:
                wait_interval = pow(
                    self.retry_interval,
                    1 + (self.retry_backoff * (message["retries"] - 1)),
                )
                retry_time = int(time() + wait_interval)
                retry_msg = str.encode(
                    json.dumps(message),
                )
                await self.redis.zadd(
                    self.retry_topic,
                    {retry_msg: retry_time},
                )
                zadd_sent = True
            except (RedisError, RedisClusterException) as err:
                await asyncio.sleep(1)
                logging.exception(f"Unexpected redis client exception (zadd): {err}")

    async def process_retries(self):
        """Process retries."""
        while self.running:
            zrangebyscore_rec = False
            while not zrangebyscore_rec:
                max_score = int(time())
                try:
                    rows = await self.redis.zrangebyscore(
                        name=self.retry_topic,
                        min=0,
                        max=max_score,
                        start=0,
                        num=10,
                    )
                    zrangebyscore_rec = True
                except (RedisError, RedisClusterException) as err:
                    await asyncio.sleep(1)
                    logging.exception(
                        f"Unexpected redis client exception (zrangebyscore): {err}"
                    )
            if rows:
                for message in rows:
                    zrem_rec = False
                    while not zrem_rec:
                        try:
                            count = await self.redis.zrem(
                                self.retry_topic,
                                message,
                            )
                            zrem_rec = True
                        except (RedisError, RedisClusterException) as err:
                            await asyncio.sleep(1)
                            logging.exception(
                                f"Unexpected redis client exception (zrem): {err}"
                            )
                    if count == 0:
                        # message removed by another process
                        continue
                    msg_sent = False
                    while not msg_sent:
                        try:
                            await self.redis.rpush(self.outbound_topic, message)
                            msg_sent = True
                        except (RedisError, RedisClusterException) as err:
                            await asyncio.sleep(1)
                            logging.exception(
                                f"Unexpected redis client exception (rpush): {err}"
                            )
            else:
                await asyncio.sleep(self.retry_timedelay_s)


async def main():
    """Start Delivery service."""
    REDIS_SERVER_URL = getenv("REDIS_SERVER_URL")
    TOPIC_PREFIX = getenv("TOPIC_PREFIX", "acapy")
    STATUS_ENDPOINT_HOST = getenv("STATUS_ENDPOINT_HOST")
    STATUS_ENDPOINT_PORT = getenv("STATUS_ENDPOINT_PORT")
    STATUS_ENDPOINT_API_KEY = getenv("STATUS_ENDPOINT_API_KEY")
    OUTBOUND_TOPIC = f"{TOPIC_PREFIX}_outbound"
    OUTBOUND_RETRY_TOPIC = f"{TOPIC_PREFIX}_outbound_retry"
    tasks = []
    if not REDIS_SERVER_URL:
        raise SystemExit("No Redis host/connection provided.")
    handler = Deliverer(REDIS_SERVER_URL, OUTBOUND_TOPIC, OUTBOUND_RETRY_TOPIC)
    logging.info(
        "Starting Redis outbound message delivery agent with args: "
        f"{REDIS_SERVER_URL}, {TOPIC_PREFIX}, {OUTBOUND_TOPIC}, {OUTBOUND_RETRY_TOPIC}"
    )
    tasks.append(asyncio.ensure_future(handler.run()))
    if STATUS_ENDPOINT_HOST and STATUS_ENDPOINT_PORT and STATUS_ENDPOINT_API_KEY:
        tasks.append(
            asyncio.ensure_future(
                start_status_endpoints_server(
                    STATUS_ENDPOINT_HOST,
                    STATUS_ENDPOINT_PORT,
                    STATUS_ENDPOINT_API_KEY,
                    [handler],
                )
            )
        )
    await asyncio.gather(*tasks)


def init():
    """Initialize the delivery service."""
    if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        main_task = asyncio.ensure_future(main())

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, main_task.cancel)

        try:
            with suppress(asyncio.CancelledError):
                loop.run_until_complete(main_task)
        finally:
            loop.close()


init()
