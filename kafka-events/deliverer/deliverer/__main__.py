"""Kafka consumer of outbound messages from ACA-Py."""
import asyncio
import signal
import sys
from asyncio import Queue
from contextlib import suppress
from os import getenv
from typing import List

import aiohttp
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from . import DelayPayload, OutboundPayload

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


async def consume_http_message():
    consumer = AIOKafkaConsumer(
        OUTBOUND_TOPIC, bootstrap_servers=BOOTSTRAP_SERVER, group_id=GROUP
    )

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.DummyCookieJar()
    ) as http_client:
        async with consumer:
            async for msg in consumer:
                outbound = OutboundPayload.from_bytes(msg.value)
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
                                    bootstrap_servers=BOOTSTRAP_SERVER,
                                    enable_idempotence=True,
                                ) as producer:
                                    outbound.retries += 1
                                    payload = DelayPayload(
                                        topic=msg.topic,
                                        outbound=outbound,
                                    ).to_bytes()
                                    await producer.send_and_wait(
                                        "delay_payload", payload
                                    )
                                log_error("Invalid response code:", response.status)
                    except aiohttp.ClientError as err:
                        log_error("Delivery error:", err)


async def delay_worker(queue: Queue):
    async with AIOKafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVER, enable_idempotence=True
    ) as producer:
        while True:
            msg = await queue.get()
            if msg is None:
                break
            payload = DelayPayload.from_bytes(msg.value)
            if payload.outbound.retries < 4:
                await asyncio.sleep(2 ** payload.outbound.retries)
                await producer.send_and_wait(
                    payload.topic,
                    payload.outbound.to_bytes(),
                )
            else:
                await producer.send_and_wait(
                    "failed_outbound_message",
                    payload.outbound.to_bytes(),
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
                await delay_queue.put(msg)

    finally:
        for worker in workers:
            with suppress(asyncio.CancelledError):
                worker.cancel()
                await worker


async def main():
    kafka_to_http_task = asyncio.ensure_future(consume_http_message())
    retry_kafka_to_http_msg_task = asyncio.ensure_future(retry_kafka_to_http_msg())
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
