"""Kafka consumer of outbound messages from ACA-Py."""
import asyncio
import base64
import json
import sys
from contextlib import suppress
from asyncio import Queue
from os import getenv
from typing import Dict, List
from urllib.parse import urlparse
import signal

import aiohttp
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, ConsumerRecord
from pydantic import BaseModel, PrivateAttr, validator

DEFAULT_BOOTSTRAP_SERVER = "kafka"
DEFAULT_OUTBOUND_TOPIC = "acapy-outbound-message"
DEFAULT_GROUP = "kafka_queue"
DEFAULT_QUEUE_SIZE = "5"
DEFAULT_WORKER_COUNT = "4"
OUTBOUND_TOPIC = getenv("OUTBOUND_TOPIC", DEFAULT_OUTBOUND_TOPIC)
BOOTSTRAP_SERVER = getenv("BOOTSTRAP_SERVER", DEFAULT_BOOTSTRAP_SERVER)
QUEUE_SIZE = int(getenv("DELAY_QUEUE_SIZE", DEFAULT_QUEUE_SIZE))
WORKER_COUNT = int(getenv("WORKER_COUNT", DEFAULT_WORKER_COUNT))
GROUP = getenv("GROUP", DEFAULT_GROUP)


def log_error(*args):
    print(*args, file=sys.stderr)


class OutboundPayload(BaseModel):
    headers: Dict[str, str]
    endpoint: str
    payload: bytes
    retries: int = 0

    _endpoint_scheme: str = PrivateAttr()

    class Config:
        json_encoders = {bytes: lambda v: base64.urlsafe_b64encode(v).decode()}

    def __init__(self, **data):
        super().__init__(**data)
        self._endpoint_scheme = urlparse(self.endpoint).scheme

    @validator("payload", pre=True)
    @classmethod
    def decode_payload_to_bytes(cls, v):
        assert isinstance(v, str)
        return base64.urlsafe_b64decode(v)

    @property
    def endpoint_scheme(self):
        return self._endpoint_scheme

    @classmethod
    def from_queue(cls, record: ConsumerRecord):
        assert isinstance(record.value, bytes)
        outbound = json.loads(record.value.decode("utf8"))
        return cls(**outbound)

    def to_queue(self) -> bytes:
        return str.encode(self.json(), encoding="utf8")


class DelayPayload(BaseModel):
    topic: str
    outbound: OutboundPayload

    @classmethod
    def from_queue(cls, record: ConsumerRecord):
        assert isinstance(record.value, bytes)
        payload = json.loads(record.value.decode("utf8"))
        return cls(**payload)

    def to_queue(self) -> bytes:
        return str.encode(self.json(), encoding="utf8")


async def consume_http_message():
    consumer = AIOKafkaConsumer(
        OUTBOUND_TOPIC, bootstrap_servers=BOOTSTRAP_SERVER, group_id=GROUP
    )
    http_client = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())
    async with consumer:
        async for msg in consumer:
            outbound = OutboundPayload.from_queue(msg)
            if outbound.endpoint_scheme in ["http", "https"]:
                print(f"Dispatch message to {outbound.endpoint}", flush=True)
                try:
                    async with http_client.post(
                        outbound.endpoint,
                        data=outbound.payload,
                        headers=outbound.headers,
                        timeout=10,
                    ) as response:
                        if response.status < 200 or response.status >= 300:
                            # produce delay_payload kafka event
                            async with AIOKafkaProducer(
                                bootstrap_servers=BOOTSTRAP_SERVER, enable_idempotence=True
                            ) as producer:
                                outbound.retries += 1
                                payload = DelayPayload(
                                    topic=msg.topic,
                                    outbound=outbound,
                                ).to_queue()
                                await producer.send_and_wait("delay_payload", payload)
                            log_error("Invalid response code:", response.status)
                except aiohttp.ClientError as err:
                    log_error("Delivery error:", err)




async def delay_worker(queue: Queue):
    print("Delay worker called")
    async with AIOKafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVER, enable_idempotence=True
    ) as producer:
        print("Producer initialized:", producer)
        while True:
            print("delay loop")
            msg = await queue.get()
            print("Got msg:", msg)
            if msg is None:
                break
            print(f"Processing delay_payload msg: {msg}")
            payload = DelayPayload.from_queue(msg)
            if payload.outbound.retries < 4:
                await asyncio.sleep(2 ** payload.outbound.retries)
                await producer.send_and_wait(
                    payload.topic,
                    payload.outbound,
                )
            else:
                await producer.send_and_wait(
                    "failed_outbound_message",
                    payload,
                )


async def retry_kafka_to_http_msg():
    consumer = AIOKafkaConsumer(
        "delay_payload", bootstrap_servers=BOOTSTRAP_SERVER, group_id=GROUP
    )
    delay_queue = Queue(maxsize=QUEUE_SIZE)
    workers: List[asyncio.Task] = []
    for _ in range(WORKER_COUNT):
        workers.append(asyncio.ensure_future(delay_worker(delay_queue)))

    try:
        async with consumer:
            async for msg in consumer:
                print("Consumer got message:", msg, consumer)
                await delay_queue.put(msg)

    finally:
        for worker in workers:
            with suppress(asyncio.CancelledError):
                worker.cancel()
                await worker


async def main():
    kafka_to_http_task = asyncio.create_task(consume_http_message())
    retry_kafka_to_http_msg_task = asyncio.create_task(retry_kafka_to_http_msg())
    await asyncio.gather(kafka_to_http_task, retry_kafka_to_http_msg_task)


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
