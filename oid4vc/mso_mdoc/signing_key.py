"""mso_mdoc signing key record.

A ``MdocSigningKeyRecord`` persists the EC private key and X.509 certificate
used by the issuer to sign mDoc credentials.  Records are scoped to the
current wallet session, giving multi-tenant isolation automatically.

The recommended workflow is:

1. **Generate** – ``POST /mso-mdoc/signing-keys`` creates a new EC P-256
   key pair server-side.  The response includes the ``public_key_pem`` (and
   optionally a CSR) so that the caller can submit the public key to an
   IACA for certificate signing.
2. **Attach certificate** – ``PUT /mso-mdoc/signing-keys/{id}`` uploads the
   CA-signed certificate once it has been obtained.

For pre-existing keys already registered with a public trust registry,
use ``POST /mso-mdoc/signing-keys/import`` to load the private key and
certificate in a single step.
"""

from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.messaging.models.openapi import OpenAPISchema
from marshmallow import fields


def generate_ec_p256_key_pem() -> str:
    """Generate an EC P-256 private key and return it as a PKCS8 PEM string."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def public_key_pem_from_private(private_key_pem: str) -> str:
    """Derive the PEM-encoded public key from a PEM-encoded private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def validate_cert_matches_private_key(private_key_pem: str, certificate_pem: str) -> None:
    """Raise ValueError if the certificate's public key doesn't match the private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))

    priv_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pub_bytes = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if priv_pub_bytes != cert_pub_bytes:
        raise ValueError(
            "Certificate public key does not match the signing key's private key"
        )


class MdocSigningKeyRecord(BaseRecord):
    """Persisted signing key and certificate for mDoc credential issuance."""

    RECORD_TOPIC = "mso_mdoc"
    RECORD_TYPE = "signing_key"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"doctype", "label"}

    class Meta:
        """MdocSigningKeyRecord metadata."""

        schema_class = "MdocSigningKeyRecordSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        doctype: Optional[str] = None,
        label: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        certificate_pem: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new MdocSigningKeyRecord."""
        super().__init__(id, **kwargs)
        self.doctype = doctype
        self.label = label
        self.private_key_pem = private_key_pem
        self.certificate_pem = certificate_pem

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def public_key_pem(self) -> Optional[str]:
        """Derive the public key PEM from the stored private key."""
        if not self.private_key_pem:
            return None
        try:
            return public_key_pem_from_private(self.private_key_pem)
        except (ValueError, TypeError):
            return None

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage.

        ``private_key_pem`` is included here so it is persisted, but it is
        never exposed via any API response schema.
        """
        return {
            prop: getattr(self, prop)
            for prop in ("doctype", "label", "private_key_pem", "certificate_pem")
        }


class MdocSigningKeyRecordSchema(BaseRecordSchema):
    """Schema for MdocSigningKeyRecord serialisation (responses)."""

    class Meta:
        """MdocSigningKeyRecordSchema metadata."""

        model_class = "MdocSigningKeyRecord"

    id = fields.Str(
        required=False,
        metadata={"description": "Signing key record identifier"},
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this signing key handles. "
                "Omit to use for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this signing key."},
    )
    public_key_pem = fields.Str(
        required=False,
        dump_only=True,
        metadata={
            "description": (
                "PEM-encoded public key (read-only, derived from the private key)."
            )
        },
    )
    certificate_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate (or chain) for this signing key."
            )
        },
    )


class MdocSigningKeyCreateSchema(OpenAPISchema):
    """Request schema for ``POST /mso-mdoc/signing-keys`` (generate flow)."""

    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this signing key handles. "
                "Omit to use for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this signing key."},
    )
    certificate_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate. Can be attached now or later via PUT."
            )
        },
    )


class MdocSigningKeyImportSchema(OpenAPISchema):
    """Request schema for ``POST /mso-mdoc/signing-keys/import``."""

    private_key_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM-encoded EC private key to import. "
                "Use this for pre-existing keys already registered "
                "with a public trust registry (IACA, etc.)."
            )
        },
    )
    certificate_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate (or chain) for this signing key."
            )
        },
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this signing key handles. "
                "Omit to use for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this signing key."},
    )


class MdocSigningKeyUpdateSchema(OpenAPISchema):
    """Request schema for ``PUT /mso-mdoc/signing-keys/{id}``."""

    certificate_pem = fields.Str(
        required=False,
        metadata={
            "description": (
                "PEM-encoded X.509 certificate (or chain) for this signing key."
            )
        },
    )
    doctype = fields.Str(
        required=False,
        metadata={
            "description": (
                "ISO 18013-5 doctype this signing key handles. "
                "Omit to use for all doctypes."
            ),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Human-readable label for this signing key."},
    )
