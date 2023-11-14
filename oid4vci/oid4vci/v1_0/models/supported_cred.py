"""Supported Credential Record."""

from typing import Dict, List, Optional
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class SupportedCredential(BaseRecord):
    """Supported Credential Record."""

    class Meta:
        """SupportedCredential metadata."""

        schema_class = "SupportedCredentialSchema"

    EVENT_NAMESPACE = "oid4vci"
    RECORD_ID_NAME = "supported_cred_id"
    RECORD_TYPE = "supported_cred"
    TAG_NAMES = {"scope"}

    def __init__(
        self,
        *,
        supported_cred_id: Optional[str] = None,
        state: Optional[str] = None,
        format: Optional[str] = None,
        scope=None,
        cryptographic_binding_methods_supported: Optional[List[str]] = None,
        cryptographic_suites_supported: Optional[List[str]] = None,
        proof_types_supported: Optional[List[str]] = None,
        display: Optional[List[Dict]] = None,
        credential_subject: Optional[Dict] = None,  # v11
        credential_definition: Optional[Dict] = None,  # v13
        **kwargs,
    ):
        """Initialize a new SupportedCredential Record."""
        super().__init__(supported_cred_id, state or "init", **kwargs)
        self.format = format
        self.scope = scope
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported
        self.proof_types_supported = proof_types_supported
        self.display = display
        self.credential_subject = credential_subject
        self.credential_definition = credential_definition

    def web_serialize(self) -> dict:
        """Serialize record for web."""
        return self.serialize()

    @property
    def supported_cred_id(self):
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "format",
                "scope",
                "cryptographic_binding_methods_supported",
                "cryptographic_suites_supported",
                "display",
                "credential_subject",
                "credential_definition",
            )
        }


class SupportedCredentialSchema(BaseRecordSchema):
    """Schema for SupportedCredential."""

    class Meta:
        """SupportedCredentialSchema metadata."""

        model_class = SupportedCredential

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    scope = fields.Str(
        required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": []}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    proof_types_supported = fields.List(
        fields.Str(), metadata={"example": ["Ed25519Signature2018"]}
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    credential_subject = fields.Dict(
        metadata={
            "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
            "family_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
            "degree": {},
            "gpa": {"display": [{"name": "GPA"}]},
        }
    )
    credential_definition = fields.Dict(
        metadata={
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "credentialSubject": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                "family_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                "degree": {},
                "gpa": {"display": [{"name": "GPA"}]},
            },
        },
    )
