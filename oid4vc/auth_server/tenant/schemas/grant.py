"""Schemas for grants."""

from pydantic import BaseModel, Field


class AuthorizationDetails(BaseModel):
    """Authorization details."""

    type: str = Field(..., description="Must be 'openid_credential'")
    credential_configuration_id: str = Field(
        ..., description="Credential configuration identifier"
    )

    class Config:
        """Pydantic config."""

        extra = "allow"


class PreAuthGrantIn(BaseModel):
    """Input for creating a pre-authorized code."""

    subject_id: str | None = None
    subject_metadata: dict | None = Field(
        default=None,
        description="Saved to subject.metadata when creating a subject",
        examples=[
            {"given_name": "Test", "family_name": "User", "email": "test@example.com"}
        ],
    )
    user_pin_required: bool = False
    user_pin: str | None = None
    authorization_details: list[AuthorizationDetails] | None = Field(
        default=None,
        description="Saved to pre_auth_code.authorization_details",
        examples=[
            [
                {
                    "type": "openid_credential",
                    "locations": ["https://credential-issuer.example.com"],
                    "credential_configuration_id": "UniversityDegreeCredential",
                },
                {
                    "type": "openid_credential",
                    "credential_configuration_id": "org.iso.18013.5.1.mDL",
                },
            ]
        ],
    )
    ttl_seconds: int | None = Field(
        default=None,
        description="TTL in seconds; falls back to server default",
        examples=[600],
    )


class PreAuthGrantOut(BaseModel):
    """Output for creating a pre-authorized code."""

    pre_authorized_code: str
    user_pin_required: bool
    user_pin: str | None = None
    subject_id: str
