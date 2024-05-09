"""Inbound relay service agent."""

import asyncio
import base64
import json
import logging
import signal
from contextlib import suppress
from os import getenv
from uuid import uuid4

from aiohttp import WSMessage, WSMsgType, web
from redis.asyncio import RedisCluster
from redis.exceptions import RedisClusterException, RedisError

from redis_events.v1_0.redis_queue.utils import b64_to_bytes, process_payload_recip_key
from redis_events.v1_0.status_endpoint.status_endpoints import (
    start_status_endpoints_server,
)

logging.basicConfig(
    format="%(asctime)s | %(levelname)s: %(message)s",
    level=logging.INFO,
)


class Relay:
    """Inbound WS delivery relay."""

    running = False
    ready = False

    def __init__(
        self,
        connection_url: str,
        site_host: str,
        site_port: str,
        direct_resp_topic: str,
        inbound_topic: str,
    ):
        """Initialize Relay."""
        self.site_host = site_host
        self.site_port = site_port
        self.redis = None
        self.direct_response_txn_request_map = {}
        self.direct_resp_topic = direct_resp_topic
        self.inbound_topic = inbound_topic
        self.site = None
        self.timedelay_s = 1
        self.connection_url = connection_url

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

    async def stop(self) -> None:
        """Shutdown."""
        if self.site:
            await self.site.stop()
            self.site = None

    async def process_direct_responses(self):
        """Process inbound_direct_responses and update direct_response_txn_request_map."""
        while self.running:
            msg_received = False
            while not msg_received:
                try:
                    msg = await self.redis.blpop(self.direct_resp_topic, 0.2)
                    msg_received = True
                except (RedisError, RedisClusterException) as err:
                    await asyncio.sleep(1)
                    logging.exception(f"Unexpected redis client exception: {err}")
            if not msg:
                await asyncio.sleep(0.2)
                continue
            msg = json.loads(msg[1].decode("utf8"))
            if not isinstance(msg, dict):
                logging.error("Received non-dict message")
                continue
            elif "response_data" not in msg:
                logging.error("No response provided")
                continue
            elif "txn_id" not in msg:
                logging.error("No txn_id provided")
                continue
            txn_id = msg["txn_id"]
            response_data = msg["response_data"]
            self.direct_response_txn_request_map[txn_id] = response_data
            await asyncio.sleep(self.timedelay_s)

    async def get_direct_responses(self, txn_id):
        """Get direct_response for a specific transaction/request."""
        while self.running:
            if txn_id in self.direct_response_txn_request_map:
                return self.direct_response_txn_request_map[txn_id]
            await asyncio.sleep(self.timedelay_s)


class WSRelay(Relay):
    """Inbound WS delivery relay."""

    async def run(self):
        """Run the service."""
        try:
            self.redis = RedisCluster.from_url(url=self.connection_url)
            self.ready = True
            self.running = True
            await asyncio.gather(self.start(), self.process_direct_responses())
        except (RedisError, RedisClusterException) as err:
            self.ready = False
            self.running = False
            logging.exception(f"Unexpected redis client exception: {err}")

    async def start(self):
        """Construct the http application."""
        app = web.Application()
        app.add_routes([web.get("/", self.message_handler)])
        runner = web.AppRunner(app)
        await runner.setup()
        self.site = web.TCPSite(runner, host=self.site_host, port=self.site_port)
        await self.site.start()

    async def message_handler(self, request):
        """Message handler for inbound messages."""
        ws = web.WebSocketResponse(
            autoping=True,
            heartbeat=3,
            receive_timeout=15,
        )
        await ws.prepare(request)
        loop = asyncio.get_event_loop()
        inbound = loop.create_task(ws.receive())
        while not ws.closed:
            await asyncio.wait((inbound), return_when=asyncio.FIRST_COMPLETED)
            if inbound.done():
                msg: WSMessage = inbound.result()
                if isinstance(msg.data, str):
                    message_data = (msg.data).encode("utf-8")
                else:
                    message_data = msg.data
                if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
                    message_dict = json.loads(msg.data)
                    direct_response_request = False
                    transport_dec = message_dict.get("~transport")
                    if transport_dec:
                        direct_response_mode = transport_dec.get("return_route")
                        if direct_response_mode and direct_response_mode != "none":
                            direct_response_request = True
                    txn_id = str(uuid4())
                    if direct_response_request:
                        self.direct_response_txn_request_map[txn_id] = request
                        message = str.encode(
                            json.dumps(
                                {
                                    "payload": base64.urlsafe_b64encode(
                                        message_data
                                    ).decode(),
                                    "txn_id": txn_id,
                                    "transport_type": "ws",
                                }
                            )
                        )
                        response_sent = False
                        while not response_sent:
                            recip_key_incl_topic, _ = await process_payload_recip_key(
                                self.redis, message_data, self.inbound_topic
                            )
                            try:
                                await self.redis.rpush(recip_key_incl_topic, message)
                                response_sent = True
                            except (RedisError, RedisClusterException) as err:
                                await asyncio.sleep(1)
                                logging.exception(
                                    f"Unexpected redis client exception: {err}"
                                )
                        try:
                            response_data = await asyncio.wait_for(
                                self.get_direct_responses(
                                    txn_id=txn_id,
                                ),
                                15,
                            )
                            response = b64_to_bytes(response_data["response"])
                            if response:
                                if isinstance(response, bytes):
                                    await ws.send_bytes(response)
                                else:
                                    await ws.send_str(response)
                        except asyncio.TimeoutError:
                            pass
                    else:
                        logging.info(f"Message received from {request.remote}")
                        message = str.encode(
                            json.dumps(
                                {
                                    "payload": base64.urlsafe_b64encode(
                                        message_data
                                    ).decode(),
                                    "transport_type": "ws",
                                }
                            )
                        )
                        msg_sent = False
                        while not msg_sent:
                            recip_key_incl_topic, _ = await process_payload_recip_key(
                                self.redis, message_data, self.inbound_topic
                            )
                            try:
                                await self.redis.rpush(recip_key_incl_topic, message)
                                msg_sent = True
                            except (RedisError, RedisClusterException) as err:
                                await asyncio.sleep(1)
                                logging.exception(
                                    f"Unexpected redis client exception: {err}"
                                )
                elif msg.type == WSMsgType.ERROR:
                    logging.error(
                        "Websocket connection closed with exception: %s",
                        ws.exception(),
                    )
                else:
                    logging.error(
                        "Unexpected Websocket message type received: %s: %s, %s",
                        msg.type,
                        msg.data,
                        msg.extra,
                    )
                if not ws.closed:
                    inbound = loop.create_task(ws.receive())
        if inbound and not inbound.done():
            inbound.cancel()
        if not ws.closed:
            await ws.close()
        logging.error("Websocket connection closed")
        return ws


class HttpRelay(Relay):
    """Inbound HTTP delivery service."""

    async def run(self):
        """Run the service."""
        try:
            self.redis = RedisCluster.from_url(url=self.connection_url)
            self.ready = True
            self.running = True
            await asyncio.gather(self.start(), self.process_direct_responses())
        except (RedisError, RedisClusterException) as err:
            self.ready = False
            self.running = False
            logging.exception(f"Unexpected redis client exception: {err}")

    async def start(self):
        """Construct the aiohttp application."""
        app = web.Application()
        app.add_routes([web.get("/", self.invite_handler)])
        app.add_routes([web.post("/", self.message_handler)])
        runner = web.AppRunner(app)
        await runner.setup()
        self.site = web.TCPSite(runner, host=self.site_host, port=self.site_port)
        await self.site.start()

    async def invite_handler(self, request):
        """Handle inbound invitation."""
        if request.query.get("c_i"):
            return web.Response(
                text="You have received a connection invitation. To accept the "
                "invitation, paste it into your agent application."
            )
        else:
            return web.Response(status=200)

    async def message_handler(self, request):
        """Message handler for inbound messages."""
        ctype = request.headers.get("content-type", "")
        if ctype.split(";", 1)[0].lower() == "application/json":
            body = await request.text()
        else:
            body = await request.read()
        if isinstance(body, str):
            message_data = body.encode("utf-8")
        else:
            message_data = body
        message_dict = json.loads(body)
        direct_response_request = False
        transport_dec = message_dict.get("~transport")
        if transport_dec:
            direct_response_mode = transport_dec.get("return_route")
            if direct_response_mode and direct_response_mode != "none":
                direct_response_request = True
        txn_id = str(uuid4())
        if direct_response_request:
            self.direct_response_txn_request_map[txn_id] = request
            message = str.encode(
                json.dumps(
                    {
                        "payload": base64.urlsafe_b64encode(message_data).decode(),
                        "txn_id": txn_id,
                        "transport_type": "http",
                    }
                )
            )
            response_sent = False
            while not response_sent:
                recip_key_incl_topic, _ = await process_payload_recip_key(
                    self.redis, message_data, self.inbound_topic
                )
                try:
                    await self.redis.rpush(recip_key_incl_topic, message)
                    response_sent = True
                except (RedisError, RedisClusterException) as err:
                    await asyncio.sleep(1)
                    logging.exception(f"Unexpected redis client exception: {err}")
            try:
                response_data = await asyncio.wait_for(
                    self.get_direct_responses(
                        txn_id=txn_id,
                    ),
                    15,
                )
                response = b64_to_bytes(response_data["response"])
                content_type = (
                    response_data["content_type"]
                    if "content_type" in response_data
                    else "application/json"
                )
                if response:
                    if isinstance(response, bytes):
                        logging.error(str(response))
                        logging.error(str(response_data["response"]))
                        response = response.decode()
                    return web.Response(
                        text=response,
                        status=200,
                        headers={"Content-Type": content_type},
                    )
            except asyncio.TimeoutError:
                return web.Response(status=200)
        else:
            logging.info(f"Message received from {request.remote}")
            message = str.encode(
                json.dumps(
                    {
                        "payload": base64.urlsafe_b64encode(message_data).decode(),
                        "transport_type": "http",
                    }
                )
            )
            msg_sent = False
            while not msg_sent:
                recip_key_incl_topic, _ = await process_payload_recip_key(
                    self.redis, message_data, self.inbound_topic
                )
                try:
                    await self.redis.rpush(recip_key_incl_topic, message)
                    msg_sent = True
                except (RedisError, RedisClusterException) as err:
                    await asyncio.sleep(1)
                    logging.exception(f"Unexpected redis client exception: {err}")
            return web.Response(status=200)


async def main():
    """Start services."""
    REDIS_SERVER_URL = getenv("REDIS_SERVER_URL")
    TOPIC_PREFIX = getenv("TOPIC_PREFIX", "acapy")
    STATUS_ENDPOINT_HOST = getenv("STATUS_ENDPOINT_HOST")
    STATUS_ENDPOINT_PORT = getenv("STATUS_ENDPOINT_PORT")
    STATUS_ENDPOINT_API_KEY = getenv("STATUS_ENDPOINT_API_KEY")
    INBOUND_TRANSPORT_CONFIG = getenv("INBOUND_TRANSPORT_CONFIG")
    if not REDIS_SERVER_URL:
        raise SystemExit("No Redis host/connection provided.")
    if not INBOUND_TRANSPORT_CONFIG:
        raise SystemExit("No inbound transport config provided.")
    INBOUND_MSG_TOPIC = f"{TOPIC_PREFIX}_inbound"
    INBOUND_MSG_DIRECT_RESP = f"{TOPIC_PREFIX}_inbound_direct_response"
    handlers = []
    tasks = []
    for inbound_transport in json.loads(INBOUND_TRANSPORT_CONFIG):
        transport_type, site_host, site_port = inbound_transport
        if transport_type == "ws":
            logging.info(
                "Starting Redis ws inbound delivery service agent "
                f"with args: {site_host}, {site_port}"
            )
            handler = WSRelay(
                REDIS_SERVER_URL,
                site_host,
                site_port,
                INBOUND_MSG_DIRECT_RESP,
                INBOUND_MSG_TOPIC,
            )
            handlers.append(handler)
        elif transport_type == "http":
            logging.info(
                "Starting Redis http inbound delivery service agent "
                f"with args: {site_host}, {site_port}"
            )
            handler = HttpRelay(
                REDIS_SERVER_URL,
                site_host,
                site_port,
                INBOUND_MSG_DIRECT_RESP,
                INBOUND_MSG_TOPIC,
            )
            handlers.append(handler)
        else:
            raise SystemExit("Only ws and http transport type are supported.")
        tasks.append(asyncio.ensure_future(handler.run()))
    if STATUS_ENDPOINT_HOST and STATUS_ENDPOINT_PORT and STATUS_ENDPOINT_API_KEY:
        tasks.append(
            asyncio.ensure_future(
                start_status_endpoints_server(
                    STATUS_ENDPOINT_HOST,
                    STATUS_ENDPOINT_PORT,
                    STATUS_ENDPOINT_API_KEY,
                    handlers,
                )
            )
        )
    await asyncio.gather(*tasks)


def init():
    """Initialize the inbound relay service agent."""
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
