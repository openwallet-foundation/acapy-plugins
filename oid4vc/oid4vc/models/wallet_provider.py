"""Wallet Provider record: trusted signers of Key Attestations."""

from typing import Any, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class WalletProvider(BaseRecord):
    """Wallet Provider trusted to sign Key Attestations (OID4VCI Appendix D)."""

    class Meta:
        """WalletProvider metadata."""

        schema_class = "WalletProviderSchema"

    RECORD_TOPIC = "oid4vci"
    RECORD_TYPE = "oid4vci_wallet_provider"
    RECORD_ID_NAME = "wallet_provider_id"
    TAG_NAMES = {"iss", "active"}

    def __init__(
        self,
        *,
        wallet_provider_id: Optional[str] = None,
        iss: str,
        jwks: Optional[dict[str, Any]] = None,
        jwks_uri: Optional[str] = None,
        name: Optional[str] = None,
        active: bool = True,
        **kwargs,
    ):
        """Initialize a new WalletProvider."""
        super().__init__(wallet_provider_id, **kwargs)
        self.iss = iss
        self.jwks = jwks
        self.jwks_uri = jwks_uri
        self.name = name
        self.active = active

    @property
    def wallet_provider_id(self) -> Optional[str]:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def tags(self) -> dict:
        """Return tags with `active` stringified for Askar."""
        result = super().tags
        if "active" in result:
            result["active"] = str(result["active"])
        return result

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in ("iss", "jwks", "jwks_uri", "name", "active")
        }


class WalletProviderSchema(BaseRecordSchema):
    """WalletProvider schema."""

    class Meta:
        """WalletProviderSchema metadata."""

        model_class = "WalletProvider"

    wallet_provider_id = fields.Str(
        required=False, metadata={"description": "Wallet Provider record identifier"}
    )
    iss = fields.Str(
        required=True,
        metadata={
            "description": "Issuer of the provider's Key Attestations, matched verbatim",
            "example": "https://wallet.example.com",
        },
    )
    jwks = fields.Dict(
        required=False,
        allow_none=True,
        metadata={"description": "Inline JWKS with the provider's signing keys"},
    )
    jwks_uri = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "https URL of the provider's JWKS"},
    )
    name = fields.Str(
        required=False, allow_none=True, metadata={"description": "Display name"}
    )
    active = fields.Bool(
        required=False, metadata={"description": "Whether the provider is trusted"}
    )
