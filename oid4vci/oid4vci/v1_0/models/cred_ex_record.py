from typing import Any, Dict, Optional
from aries_cloudagent.messaging.models.base_record import (
    BaseRecordSchema,
    BaseExchangeRecord,
)
from marshmallow import fields


class OID4VCICredentialExchangeRecord(BaseExchangeRecord):
    class Meta:
        schema_class = "CredExRecordSchema"

    RECORD_ID_NAME = "oid4vci_ex_id"
    RECORD_TYPE = "oid4vci"
    EVENT_NAMESPACE = "oid4vci"
    TAG_NAMES = {"nonce", "pin", "token"}

    def __init__(
        self,
        *,
        credential_supported_id=None,
        credential_subject: Optional[Dict[str, Any]] = None,
        nonce=None,
        pin=None,
        token=None,
        **kwargs,
    ):
        super().__init__(
            None,
            state="init",
            **kwargs,
        )
        self.credential_supported_id = credential_supported_id
        self.credential_subject = credential_subject  # (received from submit)
        self.nonce = nonce  # in offer
        self.pin = pin  # (when relevant)
        self.token = token

    @property
    def credential_exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id


# TODO: add validation
class CredExRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = OID4VCICredentialExchangeRecord

    credential_supported_id = fields.Str(
        required=True,
        metadata={
            "description": "Identifier used to identify credential supported record",
        },
    )
    credential_subject = (
        fields.Dict(
            required=True,
            metadata={
                "description": "desired claim and value in credential",
            },
        ),
    )
    nonce = (
        fields.Str(
            required=False,
        ),
    )
    pin = (
        fields.Str(
            required=False,
        ),
    )
    token = fields.Str(
        required=False,
    )
