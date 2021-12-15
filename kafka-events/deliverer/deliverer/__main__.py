"""Kafka consumer of outbound messages from ACA-Py."""
import asyncio
import signal
import sys
from contextlib import suppress
from os import getenv
from typing import List

import aiohttp
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from . import OutboundPayload

DEFAULT_BOOTSTRAP_SERVER = "kafka"
DEFAULT_OUTBOUND_TOPIC = "acapy-outbound-message"
DEFAULT_GROUP = "kafka_queue"
OUTBOUND_TOPIC = getenv("OUTBOUND_TOPIC", DEFAULT_OUTBOUND_TOPIC)
BOOTSTRAP_SERVER = getenv("BOOTSTRAP_SERVER", DEFAULT_BOOTSTRAP_SERVER)
MAX_RETRIES = getenv("DELIVERER_MAX_RETRIES", 3)
GROUP = getenv("GROUP", DEFAULT_GROUP)


def log_error(*args):
    print(*args, file=sys.stderr)


async def consume_http_message():
    consumer = AIOKafkaConsumer(
        OUTBOUND_TOPIC,
        bootstrap_servers=BOOTSTRAP_SERVER,
        group_id=GROUP,
        enable_auto_commit=False,
    )

    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.DummyCookieJar()
    ) as http_client:
        async with consumer:
            async for msg in consumer:
                outbound = OutboundPayload.from_bytes(msg.value)
                if outbound.endpoint_scheme in ["http", "https"]:
                    print(f"Dispatch message to {outbound.endpoint}", flush=True)
                    for retries in range(MAX_RETRIES):
                        try:
                            if retries == (MAX_RETRIES - 1):
                                log_error("Failed outbound message, to many attempts.")
                                async with AIOKafkaProducer(
                                    bootstrap_servers=BOOTSTRAP_SERVER,
                                    enable_idempotence=True,
                                ) as producer:
                                    await producer.send_and_wait(
                                        "failed_outbound_message", msg.value
                                    )
                                await consumer.commit()
                                break
                            async with http_client.post(
                                outbound.endpoint,
                                data=outbound.payload,
                                headers=outbound.headers,
                                timeout=10,
                            ) as response:
                                if response.status < 200 or response.status >= 300:
                                    await asyncio.sleep(2 ** retries)
                                    log_error("Invalid response code:", response.status)
                                else:
                                    await consumer.commit()
                                    break
                        except aiohttp.ClientError as err:
                            log_error("Delivery error:", err)
                            async with AIOKafkaProducer(
                                bootstrap_servers=BOOTSTRAP_SERVER,
                                enable_idempotence=True,
                            ) as producer:
                                await producer.send_and_wait(
                                    "failed_outbound_message", msg.value
                                )
                                await consumer.commit()


async def main():
    await consume_http_message()


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
