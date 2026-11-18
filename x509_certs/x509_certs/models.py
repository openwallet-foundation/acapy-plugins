"""X.509 certificate and trust anchor records."""

from typing import List, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields, validate

CERTIFICATE_PURPOSES = ("mdoc_ds", "sd_jwt_vc_issuer")
ANCHOR_PURPOSES = ("iaca", "sd_jwt_vc_ca")
# Certificate purpose -> the anchor purpose that may verify it.
ANCHOR_PURPOSE_FOR = {"mdoc_ds": "iaca", "sd_jwt_vc_issuer": "sd_jwt_vc_ca"}


class X509CertificateRecord(BaseRecord):
    """A certificate chain whose leaf is a wallet key."""

    class Meta:
        """X509CertificateRecord metadata."""

        schema_class = "X509CertificateRecordSchema"

    RECORD_TYPE = "x509_certificate"
    RECORD_ID_NAME = "cert_id"
    TAG_NAMES = {"multikey", "purpose", "subject", "not_before", "not_after"}

    def __init__(
        self,
        *,
        cert_id: Optional[str] = None,
        multikey: str,
        purpose: str,
        x5c: List[str],
        subject: str,
        issuer: str,
        not_before: str,
        not_after: str,
        sans: Optional[List[str]] = None,
        **kwargs,
    ):
        """Initialize a certificate record."""
        super().__init__(cert_id, **kwargs)
        self.multikey = multikey
        self.purpose = purpose
        self.x5c = x5c
        self.subject = subject
        self.issuer = issuer
        self.not_before = not_before
        self.not_after = not_after
        self.sans = sans or []

    @property
    def cert_id(self) -> str:
        """Accessor for the record identifier."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "multikey",
                "purpose",
                "x5c",
                "subject",
                "issuer",
                "not_before",
                "not_after",
                "sans",
            )
        }


class X509CertificateRecordSchema(BaseRecordSchema):
    """X509CertificateRecord schema."""

    class Meta:
        """X509CertificateRecordSchema metadata."""

        model_class = "X509CertificateRecord"

    cert_id = fields.Str(required=False, metadata={"description": "Certificate id"})
    multikey = fields.Str(
        required=True,
        metadata={
            "description": "Multikey of the leaf certificate's wallet key",
            "example": "zDnaeZv4cPZ9zVfMvxWdjnXc1hFXY9LYM894FyZpVsGHnx3oG",
        },
    )
    purpose = fields.Str(
        required=True,
        validate=validate.OneOf(CERTIFICATE_PURPOSES),
        metadata={"description": "Certificate purpose", "example": "sd_jwt_vc_issuer"},
    )
    x5c = fields.List(
        fields.Str(),
        required=True,
        metadata={"description": "Chain as standard base64 DER, leaf first"},
    )
    subject = fields.Str(required=True, metadata={"description": "Leaf subject"})
    issuer = fields.Str(required=True, metadata={"description": "Leaf issuer"})
    not_before = fields.Str(required=True, metadata={"description": "Leaf notBefore"})
    not_after = fields.Str(required=True, metadata={"description": "Leaf notAfter"})
    sans = fields.List(
        fields.Str(), required=False, metadata={"description": "Leaf SANs"}
    )


class X509TrustAnchorRecord(BaseRecord):
    """A CA certificate trusted for one anchor purpose."""

    class Meta:
        """X509TrustAnchorRecord metadata."""

        schema_class = "X509TrustAnchorRecordSchema"

    RECORD_TYPE = "x509_trust_anchor"
    RECORD_ID_NAME = "anchor_id"
    TAG_NAMES = {"purpose", "subject"}

    def __init__(
        self,
        *,
        anchor_id: Optional[str] = None,
        purpose: str,
        certificate_pem: str,
        subject: str,
        not_after: str,
        label: Optional[str] = None,
        **kwargs,
    ):
        """Initialize a trust anchor record."""
        super().__init__(anchor_id, **kwargs)
        self.purpose = purpose
        self.certificate_pem = certificate_pem
        self.subject = subject
        self.not_after = not_after
        self.label = label

    @property
    def anchor_id(self) -> str:
        """Accessor for the record identifier."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in ("purpose", "certificate_pem", "subject", "not_after", "label")
        }


class X509TrustAnchorRecordSchema(BaseRecordSchema):
    """X509TrustAnchorRecord schema."""

    class Meta:
        """X509TrustAnchorRecordSchema metadata."""

        model_class = "X509TrustAnchorRecord"

    anchor_id = fields.Str(required=False, metadata={"description": "Anchor id"})
    purpose = fields.Str(
        required=True,
        validate=validate.OneOf(ANCHOR_PURPOSES),
        metadata={"description": "Anchor purpose", "example": "sd_jwt_vc_ca"},
    )
    certificate_pem = fields.Str(
        required=True, metadata={"description": "PEM-encoded CA certificate"}
    )
    subject = fields.Str(required=True, metadata={"description": "Certificate subject"})
    not_after = fields.Str(
        required=True, metadata={"description": "Certificate notAfter"}
    )
    label = fields.Str(required=False, metadata={"description": "Human-readable label"})
