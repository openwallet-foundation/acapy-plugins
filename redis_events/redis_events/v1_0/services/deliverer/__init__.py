import base64
import json
from urllib.parse import urlparse

from pydantic import BaseModel, PrivateAttr, validator


class NoneDefaultModel(BaseModel):
    """Pydantic model that allows None as a default value."""
    @validator("*", pre=True)
    def not_none(cls, v, field):
        """If the value is None, return the default value."""
        if all(
            (
                # Cater for the occasion where field.default in (0, False)
                getattr(field, "default", None) is not None,
                v is None,
            )
        ):
            return field.default
        else:
            return v


class RedisQueuePayload(NoneDefaultModel):
    """Base class for payloads that are sent to the Redis queue."""
    class Config:
        """Pydantic config."""
        json_encoders = {bytes: lambda v: base64.urlsafe_b64encode(v).decode()}

    @classmethod
    def from_bytes(cls, value: bytes):
        """Deserialize a bytes object into a Pydantic model."""
        payload = json.loads(value.decode("utf8"))
        return cls(**payload)

    def to_bytes(self) -> bytes:
        """Serialize a Pydantic model into a bytes object."""
        return str.encode(self.json(), encoding="utf8")


class Service(BaseModel):
    """Service model."""
    url: str


class OutboundPayload(RedisQueuePayload):
    """Payload to be sent from the Redis queue."""
    service: Service
    payload: bytes
    headers: dict = {}
    retries: int = 0
    _endpoint_scheme: str = PrivateAttr()

    def __init__(self, **data):
        """Initialize the model."""
        super().__init__(**data)
        self._endpoint_scheme = urlparse(self.service.url).scheme

    @validator("payload", pre=True)
    @classmethod
    def decode_payload_to_bytes(cls, v):
        """Decode payload model to bytes."""""
        assert isinstance(v, str)
        return base64.urlsafe_b64decode(v)

    @property
    def endpoint_scheme(self):
        """Return the endpoint scheme."""
        return self._endpoint_scheme
