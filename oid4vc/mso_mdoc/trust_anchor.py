"""mso_mdoc trust anchor record.

A ``TrustAnchorRecord`` persists a single PEM-encoded X.509 certificate that
is trusted as a CA when verifying mDoc issuer signatures.  Records are scoped
to the current wallet session, giving multi-tenant isolation automatically.
"""

from typing import Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields, validate


class TrustAnchorRecord(BaseRecord):
    """Persisted X.509 trust anchor for mDoc credential verification."""

    RECORD_TOPIC = "mso_mdoc"
    RECORD_TYPE = "trust_anchor"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"doctype", "purpose"}

    class Meta:
        """TrustAnchorRecord metadata."""

        schema_class = "TrustAnchorRecordSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        doctype: Optional[str] = None,
        purpose: str = "iaca",
        label: Optional[str] = None,
        certificate_pem: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new TrustAnchorRecord."""
        super().__init__(id, **kwargs)
        self.doctype = doctype
        self.purpose = purpose
        self.label = label
        self.certificate_pem = certificate_pem

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in ("doctype", "purpose", "label", "certificate_pem")
        }


class TrustAnchorRecordSchema(BaseRecordSchema):
    """Schema for TrustAnchorRecord serialisation."""

    class Meta:
        """TrustAnchorRecordSchema metadata."""

        model_class = "TrustAnchorRecord"

    id = fields.Str(
        required=False,
        metadata={"description": "Trust anchor record identifier"},
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this anchor applies to. "
                "Omit to trust for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    purpose = fields.Str(
        required=False,
        load_default="iaca",
        validate=validate.OneOf(["iaca", "reader_auth"]),
        metadata={
            "description": (
                "Trust anchor purpose: 'iaca' for issuer CA certificates, "
                "'reader_auth' for reader authentication certificates."
            ),
            "example": "iaca",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this trust anchor."},
    )
    certificate_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate (may include a chain separated "
                "by newlines).  The first certificate in the PEM is used as the "
                "trust anchor; subsequent certificates are treated as intermediates."
            )
        },
    )
