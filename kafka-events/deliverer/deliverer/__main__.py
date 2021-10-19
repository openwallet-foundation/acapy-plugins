"""Kafka consumer of outbound messages from ACA-Py."""
import asyncio
import base64
import json
from os import getenv
import sys
from urllib.parse import urlparse
from typing import Dict
from pydantic import BaseModel, PrivateAttr, validator

import aiohttp
from aiokafka import AIOKafkaConsumer, ConsumerRecord


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
    retries: int
    outbound: OutboundPayload

    @classmethod
    def from_queue(cls, record: ConsumerRecord):
        assert isinstance(record.value, bytes)
        payload = json.loads(record.value.decode("utf8"))
        return cls(**payload)

    def to_queue(self) -> bytes:
        return str.encode(self.json(), encoding="utf8")


async def main():
    consumer = AIOKafkaConsumer(
        OUTBOUND_TOPIC, bootstrap_servers=BOOTSTRAP_SERVER, group_id=GROUP
    )
    http_client = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())
    async with consumer:
        async for msg in consumer:
            outbound = OutboundPayload.from_queue(msg)
            if (
                outbound.endpoint_scheme == "http"
                or outbound.endpoint_scheme == "https"
            ):
                print(f"Dispatch message to {outbound.endpoint}", flush=True)
                try:
                    response = await http_client.post(
                        outbound.endpoint,
                        data=outbound.payload,
                        headers=outbound.headers,
                        timeout=10,
                    )
                except aiohttp.ClientError as err:
                    log_error("Delivery error:", err)
                else:
                    if response.status < 200 or response.status >= 300:
                        log_error("Invalid response code:", response.status)


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
