"""Exchange record for OID4VCI."""

from datetime import datetime
from typing import Any, Dict, Optional, Union

from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseRecordSchema,
)
from acapy_agent.messaging.util import datetime_to_str
from acapy_agent.messaging.valid import (
    ISO8601_DATETIME_EXAMPLE,
    ISO8601_DATETIME_VALIDATE,
    Uri,
)
from marshmallow import fields
from uuid_utils import uuid4


class OID4VCIExchangeRecord(BaseExchangeRecord):
    """OID4VCI Exchange Record."""

    class Meta:
        """OID4VCI Exchange Record metadata."""

        schema_class = "OID4VCIExchangeRecordSchema"

    RECORD_TYPE = "oid4vci"
    # EVENT_NAMESPACE = "oid4vci"
    RECORD_TOPIC = "oid4vci"
    RECORD_ID_NAME = "exchange_id"
    STATE_CREATED = "created"
    STATE_OFFER_CREATED = "offer"
    STATE_ISSUED = "issued"
    STATE_FAILED = "failed"
    STATE_ACCEPTED = "accepted"
    STATE_DELETED = "deleted"
    STATE_SUPERCEDED = "superceded"
    STATES = (
        STATE_CREATED,
        STATE_OFFER_CREATED,
        STATE_ISSUED,
        STATE_FAILED,
        STATE_ACCEPTED,
        STATE_DELETED,
        STATE_SUPERCEDED,
    )
    TAG_NAMES = {"state", "supported_cred_id", "refresh_id", "notification_id", "code"}

    def __init__(
        self,
        *,
        exchange_id: Optional[str] = None,
        state: str,
        supported_cred_id: str,
        credential_subject: Dict[str, Any],
        verification_method: str,
        issuer_id: str,
        refresh_id: Optional[str] = None,
        notification_id: Optional[str] = None,
        notification_event: Optional[dict] = None,
        nonce: Optional[str] = None,
        pin: Optional[str] = None,
        code: Optional[str] = None,
        token: Optional[str] = None,
        expires_at: Union[str, datetime, None] = None,
        **kwargs,
    ):
        """Initialize a new OID4VCIExchangeRecord."""
        super().__init__(exchange_id, state or "init", **kwargs)
        self.supported_cred_id = supported_cred_id
        self.credential_subject = credential_subject  # (received from submit)
        self.verification_method = verification_method
        self.issuer_id = issuer_id
        self.refresh_id = refresh_id or str(uuid4())
        self.notification_id = notification_id
        self.notification_event = notification_event
        self.nonce = nonce  # in offer
        self.pin = pin  # (when relevant)
        self.code = code
        self.token = token
        self.expires_at = datetime_to_str(expires_at)

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
                "verification_method",
                "issuer_id",
                "refresh_id",
                "notification_id",
                "notification_event",
                "nonce",
                "pin",
                "code",
                "token",
                "expires_at",
            )
        }

    @classmethod
    async def retrieve_by_refresh_id(
        cls,
        session: ProfileSession,
        refresh_id: str | None,
        for_update: bool = False,
    ):
        """Retrieve an exchange record by refresh_id."""
        tag_filter: dict[str, Any] = {
            "refresh_id": refresh_id,
            "$or": [
                {"state": OID4VCIExchangeRecord.STATE_CREATED},
                {"state": OID4VCIExchangeRecord.STATE_OFFER_CREATED},
            ],
        }
        if refresh_id:
            return await cls.retrieve_by_tag_filter(
                session, tag_filter=tag_filter, for_update=for_update
            )
        return None

    @classmethod
    async def retrieve_by_notification_id(
        cls, session: ProfileSession, notification_id: str | None
    ):
        """Retrieve an exchange record by notification_id."""
        if notification_id:
            return await cls.retrieve_by_tag_filter(
                session, {"notification_id": notification_id}
            )
        return None

    @classmethod
    async def retrieve_by_code(cls, session: ProfileSession, code: str):
        """Retrieve an exchange record by code."""
        return await cls.retrieve_by_tag_filter(session, {"code": code})


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
    verification_method = fields.Str(
        required=True,
        validate=Uri(),
        metadata={
            "description": "Information used to identify the issuer keys",
            "example": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg34"
                "2Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )
    issuer_id = fields.Str(
        required=True,
        validate=Uri(),
        metadata={
            "description": "Information used to identify the issuer",
            "example": ("did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"),
        },
    )
    refresh_id = fields.Str(
        required=False,
    )
    notification_id = fields.Str(
        required=False,
    )
    notification_event = fields.Dict(
        required=False,
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
    expires_at = fields.Str(
        required=False,
        validate=ISO8601_DATETIME_VALIDATE,
        metadata={
            "description": "Expiration time",
            "example": ISO8601_DATETIME_EXAMPLE,
        },
    )
