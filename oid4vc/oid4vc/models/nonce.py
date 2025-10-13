"""Nonce record for replay prevention."""

from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.messaging.valid import (
    ISO8601_DATETIME_EXAMPLE,
    ISO8601_DATETIME_VALIDATE,
)
from acapy_agent.messaging.util import datetime_now, str_to_datetime
from marshmallow import fields


class Nonce(BaseRecord):
    """Nonce record for replay prevention."""

    RECORD_TOPIC = "oid4vci"
    RECORD_TYPE = "nonce"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"nonce_value", "used"}

    class Meta:
        """Nonce Metadata."""

        schema_class = "NonceSchema"

    def __init__(
        self,
        *,
        id: str | None = None,
        nonce_value: str,
        used: bool,
        issued_at: str,
        expires_at: str,
        **kwargs,
    ):
        """Initialize a new Nonce."""
        super().__init__(id, **kwargs)
        self.nonce_value = nonce_value
        self.used = used
        self.issued_at = issued_at
        self.expires_at = expires_at

    @property
    def id(self) -> str | None:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the nonce record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "nonce_value",
                "used",
                "issued_at",
                "expires_at",
            )
        }

    @classmethod
    async def redeem_by_value(cls, session: ProfileSession, nonce_value: str | None):
        """Retrieve a nonce record by its value."""
        if not nonce_value:
            return None

        record = await cls.retrieve_by_tag_filter(
            session, {"nonce_value": nonce_value, "used": False}, for_update=True
        )
        if record:
            expires_after = datetime_now()
            expires_at = str_to_datetime(record.expires_at)
            if not expires_at or expires_at <= expires_after:
                return None
        record.used = True
        await record.save(session, reason="mark nonce used")
        return record


class NonceSchema(BaseRecordSchema):
    """Nonce record schema."""

    class Meta:
        """Nonce record schema metadata."""

        model_class = "Nonce"

    id = fields.Str(
        required=False,
        description="Primary key identifier for the nonce record",
    )
    nonce_value = fields.Str(
        required=True,
        metadata={"description": "Unique nonce value"},
    )
    used = fields.Bool(
        required=True,
        metadata={"description": "Whether the nonce has been used"},
    )
    issued_at = fields.Str(
        required=True,
        validate=ISO8601_DATETIME_VALIDATE,
        metadata={
            "description": "Timestamp when nonce was issued",
            "example": ISO8601_DATETIME_EXAMPLE,
        },
    )
    expires_at = fields.Str(
        required=True,
        validate=ISO8601_DATETIME_VALIDATE,
        metadata={
            "description": "Timestamp when nonce expires",
            "example": ISO8601_DATETIME_EXAMPLE,
        },
    )
