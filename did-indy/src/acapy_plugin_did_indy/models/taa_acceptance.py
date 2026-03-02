"""Models for DID Indy."""

from typing import Optional
from marshmallow import fields
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema


class TAAAcceptance(BaseModel):
    """Model for storing TAA acceptance information."""

    class Meta:
        """TAAAcceptance metadata."""

        schema_class = "TAAAcceptanceSchema"

    def __init__(
        self,
        *,
        namespace: Optional[str] = None,
        text: Optional[str] = None,
        version: Optional[str] = None,
        digest: str = "",
        mechanism: str = "on_file",
        accepted_at: int = 0,
    ):
        """Initialize a TAAAcceptance instance.

        Args:
            namespace: The ledger namespace
            text: The TAA text
            version: The TAA version
            digest: The TAA digest
            mechanism: The acceptance mechanism
            accepted_at: Time of acceptance
        """
        super().__init__()
        self.namespace = namespace
        self.text = text
        self.version = version
        self.digest = digest
        self.mechanism = mechanism
        self.accepted_at = accepted_at


class TAAAcceptanceSchema(BaseModelSchema):
    """Schema for TAAAcceptance model."""

    class Meta:
        """TAAAcceptanceSchema metadata."""

        model_class = TAAAcceptance

    namespace = fields.Str(required=True)
    text = fields.Str(required=True)
    version = fields.Str(required=True)
    digest = fields.Str(required=True)
    mechanism = fields.Str(required=False, default="on_file")
    accepted_at = fields.Str(required=False)
