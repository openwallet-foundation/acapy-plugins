"""Supported Credential Record."""

import logging
from typing import Dict, List, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

LOGGER = logging.getLogger(__name__)


class SupportedCredential(BaseRecord):
    """Supported Credential Record."""

    class Meta:
        """SupportedCredential metadata."""

        schema_class = "SupportedCredentialSchema"

    RECORD_TOPIC = "oid4vci"
    RECORD_ID_NAME = "supported_cred_id"
    RECORD_TYPE = "supported_cred"
    TAG_NAMES = {"identifier", "format"}

    def __init__(
        self,
        *,
        supported_cred_id: Optional[str] = None,
        format: Optional[str] = None,
        identifier: Optional[str] = None,
        scope: Optional[str] = None,
        credential_signing_alg_values_supported: Optional[List[str]] = None,
        cryptographic_binding_methods_supported: Optional[List[str]] = None,
        cryptographic_suites_supported: Optional[List[str]] = None,  # Deprecated
        proof_types_supported: Optional[Dict] = None,
        credential_metadata: Optional[Dict] = None,
        display: Optional[List[Dict]] = None,  # Deprecated
        format_data: Optional[Dict] = None,  # Deprecated
        vc_additional_data: Optional[Dict] = None,  # Deprecated Non-standard
        **kwargs,
    ):
        """Initialize a new SupportedCredential Record.

        Args:
            supported_cred_id (Optional[str]):
                Record identifier (internal use only).
            format (Optional[str]):
                Format identifier of the credential. e.g. jwt_vc_json
            identifier (Optional[str]):
                Identifier of the supported credential metadata.
            scope (Optional[str]):
                Scope value for this credential.
            credential_signing_alg_values_supported (Optional[List[str]]):
                Algorithms used to sign credentials.
            cryptographic_binding_methods_supported (Optional[List[str]]):
                Supported cryptographic binding methods.
            cryptographic_suites_supported (Optional[List[str]]):
                (Deprecated) Supported cryptographic suites.
            proof_types_supported (Optional[Dict]):
                Supported proof types.
            credential_metadata (Optional[Dict]):
                Credential metadata for display and usage.
            display (Optional[List[Dict]]):
                (Deprecated) Display characteristics of the credential.
            format_data (Optional[Dict]):
                (Deprecated) Format specific attributes.
            vc_additional_data (Optional[Dict]):
                Additional data to include in the Verifiable Credential.
            kwargs:
                Keyword arguments to allow generic initialization of the record.
        """
        super().__init__(supported_cred_id, **kwargs)
        self.format = format
        self.identifier = identifier
        self.scope = scope
        self.credential_signing_alg_values_supported = (
            credential_signing_alg_values_supported
        )
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported  # Deprecated
        self.proof_types_supported = proof_types_supported
        self.credential_metadata = credential_metadata
        self.display = display  # Deprecated
        self.format_data = format_data  # Deprecated
        self.vc_additional_data = vc_additional_data  # Deprecated Non-standard

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
                "identifier",
                "scope",
                "credential_signing_alg_values_supported",
                "cryptographic_binding_methods_supported",
                "cryptographic_suites_supported",  # Deprecated
                "proof_types_supported",
                "credential_metadata",
                "display",  # Deprecated
                "format_data",  # Deprecated
                "vc_additional_data",  # Deprecated Non-standard
            )
        }

    def metadata(self) -> dict:
        """Return a representation of this record as issuer metadata.

        To arrive at the structure defined by the specification, it must be
        derived from this record (the record itself is not exactly aligned with
        the spec).
        """
        metadata = {
            prop: value
            for prop in (
                "display",
                "format",
                "scope",
                "credential_signing_alg_values_supported",
                "cryptographic_binding_methods_supported",
                "proof_types_supported",
                "credential_metadata",
            )
            if (value := getattr(self, prop)) is not None
        }
        # Fallback for deprecated fields
        if "credential_signing_alg_values_supported" not in metadata:
            alg_supported = getattr(self, "cryptographic_suites_supported", None)
            if alg_supported:
                metadata["credential_signing_alg_values_supported"] = alg_supported
        if metadata.get("credential_signing_alg_values_supported"):
            metadata["credential_signing_alg_values_supported"] = [
                int(value)
                if isinstance(value, str) and value.lstrip("+-").isdigit()
                else value
                for value in metadata["credential_signing_alg_values_supported"]
            ]
        if "credential_metadata" not in metadata and (
            cred_meta := getattr(self, "format_data", None)
        ):
            metadata["credential_metadata"] = cred_meta
            # Check optional claims
            claims = cred_meta.get("claims", None)
            if claims is None or claims == []:
                cred_meta.pop("claims", None)
            # Check display info
            if "display" in metadata:
                for item in metadata["display"]:
                    if "logo" in item and "url" in item["logo"]:
                        item["logo"]["uri"] = item["logo"]["url"]
                        del item["logo"]["url"]
                    if "background_image" in item and "url" in item["background_image"]:
                        item["background_image"]["uri"] = item["background_image"]["url"]
                        del item["background_image"]["url"]
                cred_meta["display"] = metadata.pop("display")
        if not metadata.get("credential_metadata", None):
            metadata.pop("credential_metadata", None)
        # Add additional VC data if present
        if self.vc_additional_data:
            metadata["vc_additional_data"] = self.vc_additional_data

        return metadata


class SupportedCredentialSchema(BaseRecordSchema):
    """Schema for SupportedCredential."""

    class Meta:
        """SupportedCredentialSchema metadata."""

        model_class = SupportedCredential

    supported_cred_id = fields.Str(
        required=False,
        description="supported credential identifier (internal use only)",
    )
    identifier = fields.Str(
        required=True,
        metadata={"example": "UniversityDegreeCredential"},
        description="Identifier of the supported credential metadata (spec 'id')",
    )
    format = fields.Str(
        required=True,
        metadata={"example": "jwt_vc_json"},
        description=(
            "A JSON string identifying the format of this Credential, "
            "e.g., jwt_vc_json or ldp_vc"
        ),
    )
    scope = fields.Str(
        required=False,
        metadata={"example": "UniversityDegree"},
        description=(
            "A JSON string identifying the scope value"
            "that this Credential Issuer supports for this particular Credential"
        ),
    )
    credential_signing_alg_values_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={"example": ["ES256K"]},
        description="Algorithms that the Issuer uses to sign the issued Credential",
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(),
        required=False,
        metadata={"example": ["jwk", "did:example"]},
        description=(
            "Representation of the cryptographic key material"
            "that the issued Credential is bound to"
        ),
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(),
        required=False,
        description="(Deprecated) Use credential_signing_alg_values_supported",
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={
            "example": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"],
                    "key_attestations_required": {
                        "key_storage": ["hardware"],
                        "user_authentication": ["biometric"],
                    },
                }
            }
        },
        description=(
            "Object describing specifics of the key proof(s) "
            "that the Credential Issuer supports"
        ),
    )
    credential_metadata = fields.Dict(
        required=False,
        metadata={
            "example": {
                "claims": [
                    {
                        "path": ["given_name"],
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    {
                        "path": ["family_name"],
                        "display": [{"name": "Surname", "locale": "en-US"}],
                    },
                    {"path": ["degree"]},
                    {
                        "path": ["gpa"],
                        "mandatory": True,
                        "display": [{"name": "GPA"}],
                    },
                ],
                "display": [
                    {
                        "name": "University Credential",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://university.example.edu/public/logo.png",
                            "alt_text": "a square logo of a university",
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
        },
        description=(
            "Object containing information relevant to the usage and display"
            "of issued Credentials"
        ),
    )
    display = fields.List(
        fields.Dict(),
        required=False,
        description="(Deprecated) Use credential_metadata.display",
    )
    format_data = fields.Dict(
        required=False,
        description="(Deprecated) Use credential_metadata.claims",
    )
    vc_additional_data = fields.Dict(
        required=False,
        metadata={
            "example": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            }
        },
        description=(
            "(Non-standard, internal use only) Additional data"
            "to include in the Verifiable Credential"
        ),
    )
