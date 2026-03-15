"""Issuer Configuration Record."""

from typing import Any, Dict, List, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class IssuerConfiguration(BaseRecord):
    """Issuer Configuration Record."""

    class Meta:
        """Issuer Configuration metadata."""

        schema_class = "IssuerConfigurationSchema"

    RECORD_TOPIC = "oid4vci"
    RECORD_ID_NAME = "configuration_id"
    RECORD_TYPE = "issuer_configuration"
    TAG_NAMES = {}

    ISSUER_ATTRS = [
        "credential_issuer",
        "authorization_servers",
        "credential_endpoint",
        "nonce_endpoint",
        "deferred_credential_endpoint",
        "notification_endpoint",
        "credential_request_encryption",
        "credential_response_encryption",
        "batch_credential_issuance",
        "display",
    ]

    def __init__(
        self,
        *,
        configuration_id: Optional[str] = None,
        credential_issuer: Optional[str] = None,
        authorization_servers: Optional[List[dict]] = None,
        credential_endpoint: Optional[str] = None,
        nonce_endpoint: Optional[str] = None,
        deferred_credential_endpoint: Optional[str] = None,
        notification_endpoint: Optional[str] = None,
        credential_request_encryption: Optional[Dict] = None,
        credential_response_encryption: Optional[Dict] = None,
        batch_credential_issuance: Optional[Dict] = None,
        display: Optional[List[Dict]] = None,
        new_with_id: bool = False,
        **kwargs,
    ):
        """Initialize a new Issuer Configuration Record."""
        super().__init__(id=configuration_id, new_with_id=new_with_id, **kwargs)
        self.credential_issuer = credential_issuer
        self.authorization_servers = authorization_servers
        self.credential_endpoint = credential_endpoint
        self.nonce_endpoint = nonce_endpoint
        self.deferred_credential_endpoint = deferred_credential_endpoint
        self.notification_endpoint = notification_endpoint
        self.credential_request_encryption = credential_request_encryption
        self.credential_response_encryption = credential_response_encryption
        self.batch_credential_issuance = batch_credential_issuance
        self.display = display

    @property
    def configuration_id(self):
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {prop: getattr(self, prop) for prop in self.ISSUER_ATTRS}

    def issuer_metadata(self, base_url: str) -> dict:
        """Return a representation of this record as issuer metadata."""
        metadata: dict[str, Any] = {
            prop: getattr(self, prop)
            for prop in self.ISSUER_ATTRS
            if getattr(self, prop) is not None
        }
        if metadata.get("authorization_servers"):
            metadata["authorization_servers"] = [
                server.get("public_url", None)
                for server in metadata["authorization_servers"]
            ]
        if not metadata.get("credential_issuer"):
            metadata["credential_issuer"] = base_url
        if not metadata.get("credential_endpoint"):
            metadata["credential_endpoint"] = f"{base_url}/credential"
        if not metadata.get("nonce_endpoint"):
            metadata["nonce_endpoint"] = f"{base_url}/nonce"
        if not metadata.get("notification_endpoint"):
            metadata["notification_endpoint"] = f"{base_url}/notification"

        return metadata


class IssuerConfigurationSchema(BaseRecordSchema):
    """Schema for Issuer Configuration."""

    class Meta:
        """SupportedCredentialSchema metadata."""

        model_class = IssuerConfiguration

    configuration_id = fields.Str(required=False, description="configuration identifier")
    credential_issuer = fields.Str(required=False, description="credential issuer")
    authorization_servers = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "public_url": "https://auth.example.com",
                    "private_url": "https://intra.example.com",
                    "auth_type": "client_secret_basic",
                    "client_credentials": {
                        "client_id": "abc123",
                        "client_secret": "xyz456",
                    },
                },
                {
                    "public_url": "https://auth.example.com",
                    "private_url": "https://intra.example.com",
                    "auth_type": "private_key_jwt",
                    "client_credentials": {
                        "client_id": "abc123",
                        "did": "wV6ydFNQYCdo2mfzvPBbF",
                    },
                },
            ]
        },
    )
    credential_endpoint = fields.Str(required=False, description="credential endpoint")
    nonce_endpoint = fields.Str(required=False, description="nonce endpoint")
    deferred_credential_endpoint = fields.Str(
        required=False, description="deferred credential endpoint"
    )
    notification_endpoint = fields.Str(
        required=False, description="notification endpoint"
    )
    credential_request_encryption = fields.Dict(
        required=False,
        metadata={
            "example": {
                "keys": [
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF4Jqk8rVqYf5UEoR2L7iB42t1R6kzjzA6o",
                        "y": "x_FEzRu9yQ1rZtQxCkVwYg1oHc3mG5m0kYqf9u0Qf6A",
                        "use": "enc",
                        "alg": "ECDH-ES",
                        "key_ops": ["deriveKey", "deriveBits"],
                        "kid": "ec-p256-enc-1",
                    }
                ]
            },
            "enc_values_supported": ["A256GCM", "A128GCM", "A128CBC-HS256"],
            "zip_values_supported": ["DEF"],
            "encryption_required": True,
        },
    )
    credential_response_encryption = fields.Dict(
        required=False,
        metadata={
            "example": {
                "alg_values_supported": [
                    "ECDH-ES",
                    "ECDH-ES+A256KW",
                    "RSA-OAEP-256",
                    "RSA-OAEP",
                ],
                "enc_values_supported": ["A256GCM", "A128GCM", "A128CBC-HS256"],
                "zip_values_supported": ["DEF"],
                "encryption_required": True,
            },
        },
    )
    batch_credential_issuance = fields.Dict(
        required=False,
        metadata={
            "example": {"batch_size": 100},
        },
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "uri": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                }
            ]
        },
    )
