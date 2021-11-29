"""Kafka consumer of outbound messages from ACA-Py."""
import asyncio
import base64
import json
import sys
from os import getenv
from typing import Dict
from urllib.parse import urlparse

import aiohttp
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, ConsumerRecord
from pydantic import BaseModel, PrivateAttr, validator


DEFAULT_BOOTSTRAP_SERVER = "kafka"
DEFAULT_OUTBOUND_TOPIC = "acapy-outbound-message"
DEFAULT_GROUP = "kafka_queue"
OUTBOUND_TOPIC = getenv("OUTBOUND_TOPIC", DEFAULT_OUTBOUND_TOPIC)
BOOTSTRAP_SERVER = getenv("BOOTSTRAP_SERVER", DEFAULT_BOOTSTRAP_SERVER)
GROUP = getenv("GROUP", DEFAULT_GROUP)


def log_error(*args):
    print(*args, file=sys.stderr)


class OutboundPayload(BaseModel):
    headers: Dict[str, str]
    endpoint: str
    payload: bytes

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
    retries: int
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
                print(f'Dispatch message to {outbound.endpoint}', flush=True)
                try:
                    response = await http_client.post(
                        outbound.endpoint,
                        data=outbound.payload,
                        headers=outbound.headers,
                        timeout=10,
                    )
                except aiohttp.ClientError as err:
                    log_error('Delivery error:', err)
                else:
                    if response.status < 200 or response.status >= 300:
                        # produce delay_payload kafka event
                        async with AIOKafkaProducer({}) as producer:
                            payload = DelayPayload.to_queue(
                                { **outbound,
                                 "topic": msg.topic,
                                 "retries": outbound.retries + 1
                                } 
                            )
                            await producer.send_and_wait(
                                'delay_payload',
                                payload
                            )
                        log_error("Invalid response code:", response.status)

async def retry_kafka_to_http_msg():
    consumer = AIOKafkaConsumer(
        "delay_payload", bootstrap_servers=BOOTSTRAP_SERVER, group_id=GROUP
    )
    async with consumer:
        async for msg in consumer:
            print(f"Processing delay_payload msg: {msg}")
            payload = DelayPayload.from_queue(msg)
            # todo: add configuration for number of retry attempts
            if (payload.retries < 4):
                await asyncio.sleep(2 ** payload.retries)
                async with AIOKafkaProducer({}) as producer:
                    payload = OutboundPayload.to_queue(
                        { **payload,
                            "retries": payload.retries
                        } 
                    )
                    del payload['topic']
                    await producer.send_and_wait(
                        payload.topic,
                        payload,
                    )
            # else, we do not handle the event again.

async def main():
    kafka_to_http_task = asyncio.create_task(consume_http_message())
    retry_kafka_to_http_msg_task = asyncio.create_task(retry_kafka_to_http_msg())


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
