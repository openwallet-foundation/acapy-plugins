import base64
import json
from typing import Dict
from urllib.parse import urlparse

from pydantic import BaseModel, PrivateAttr, validator


class KafkaQueuePayload(BaseModel):
    class Config:
        json_encoders = {bytes: lambda v: base64.urlsafe_b64encode(v).decode()}

    @classmethod
    def from_bytes(cls, value: bytes):
        payload = json.loads(value.decode("utf8"))
        return cls(**payload)

    def to_bytes(self) -> bytes:
        return str.encode(self.json(), encoding="utf8")


class OutboundPayload(KafkaQueuePayload):
    headers: Dict[str, str]
    endpoint: str
    payload: bytes
    retries: int = 0

    _endpoint_scheme: str = PrivateAttr()

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


class DelayPayload(KafkaQueuePayload):
    topic: str
    outbound: OutboundPayload
