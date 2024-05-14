import base64
import json
from urllib.parse import urlparse

from pydantic import BaseModel, PrivateAttr, validator


class KafkaQueuePayload(BaseModel):
    """Base class for payloads that are sent to the Kafka queue."""

    class Config:
        """Configuration class for KafkaQueuePayload."""

        json_encoders = {bytes: lambda v: base64.urlsafe_b64encode(v).decode()}

    @classmethod
    def from_bytes(cls, value: bytes):
        """Create a KafkaQueuePayload from a bytes object."""
        payload = json.loads(value.decode("utf8"))
        return cls(**payload)

    def to_bytes(self) -> bytes:
        """Convert the payload to a bytes object."""
        return str.encode(self.json(), encoding="utf8")


class Service(BaseModel):
    """Model for a service that can be called."""

    url: str


class OutboundPayload(KafkaQueuePayload):
    """Model for a payload that is sent to the Kafka queue."""

    service: Service
    payload: bytes
    retries: int = 0

    _endpoint_scheme: str = PrivateAttr()

    def __init__(self, **data):
        """Initialize the OutboundPayload."""
        super().__init__(**data)
        self._endpoint_scheme = urlparse(self.service.url).scheme

    @validator("payload", pre=True)
    @classmethod
    def decode_payload_to_bytes(cls, v):
        """Decode the payload to bytes."""
        assert isinstance(v, str)
        return base64.urlsafe_b64decode(v)

    @property
    def endpoint_scheme(self):
        """Return the scheme of the endpoint."""
        return self._endpoint_scheme
