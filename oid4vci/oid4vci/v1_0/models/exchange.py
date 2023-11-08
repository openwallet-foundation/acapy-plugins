"""Exchange record for OID4VCI."""

from typing import Any, Dict, Optional
from aries_cloudagent.messaging.models.base_record import (
    BaseRecordSchema,
    BaseExchangeRecord,
)
from marshmallow import fields


class OID4VCIExchangeRecord(BaseExchangeRecord):
    """OID4VCI Exchange Record."""

    class Meta:
        """OID4VCI Exchange Record metadata."""

        schema_class = "OID4VCIExchangeRecordSchema"

    RECORD_TYPE = "oid4vci"
    EVENT_NAMESPACE = "oid4vci"
    RECORD_TOPIC = "oid4vci"
    RECORD_ID_NAME = "exchange_id"
    TAG_NAMES = {"nonce", "pin", "token"}

    def __init__(
        self,
        *,
        exchange_id: Optional[str] = None,
        state: Optional[str] = None,
        supported_cred_id: Optional[str] = None,
        credential_subject: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
        pin: Optional[str] = None,
        code: Optional[str] = None,
        token: Optional[str] = None,
        **kwargs,
    ):
        """Initialize a new OID4VCIExchangeRecord."""
        super().__init__(exchange_id, state or "init", **kwargs)
        self.supported_cred_id = supported_cred_id
        self.credential_subject = credential_subject  # (received from submit)
        self.nonce = nonce  # in offer
        self.pin = pin  # (when relevant)
        self.code = code
        self.token = token

    @property
    def exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "supported_cred_id",
                "credential_subject",
                "nonce",
                "pin",
                "code",
                "token",
            )
        }


class OID4VCIExchangeRecordSchema(BaseRecordSchema):
    """OID4VCI Exchange Record Schema."""

    class Meta:
        """OID4VCI Exchange Record Schema metadata."""

        model_class = OID4VCIExchangeRecord

    exchange_id = fields.Str(
        required=False,
        description="Exchange identifier",
    )
    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Identifier used to identify credential supported record",
        },
    )
    credential_subject = fields.Dict(
        required=True,
        metadata={
            "description": "desired claim and value in credential",
        },
    )
    nonce = fields.Str(
        required=False,
    )
    pin = fields.Str(
        required=False,
    )
    token = fields.Str(
        required=False,
    )
    code = fields.Str(
        required=False,
    )
