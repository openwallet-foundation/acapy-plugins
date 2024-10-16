"""Exchange record for OID4VCI."""

from typing import Any, Dict, Optional

from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseRecordSchema,
)
from acapy_agent.messaging.valid import Uri
from marshmallow import fields


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
    STATES = (STATE_CREATED, STATE_OFFER_CREATED, STATE_ISSUED, STATE_FAILED)
    TAG_NAMES = {"state", "supported_cred_id", "code"}

    def __init__(
        self,
        *,
        exchange_id: Optional[str] = None,
        state: str,
        supported_cred_id: str,
        credential_subject: Dict[str, Any],
        verification_method: str,
        issuer_id: str,
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
        self.verification_method = verification_method
        self.issuer_id = issuer_id
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
                "verification_method",
                "issuer_id",
                "nonce",
                "pin",
                "code",
                "token",
            )
        }

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
