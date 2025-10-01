"""Schemas for client onboarding to tenant DB."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ClientIn(BaseModel):
    """Client onboarding payload."""

    client_id: str | None = Field(
        description="Client ID; if omitted, generated automatically",
        default=None,
    )
    client_auth_method: str | None = Field(
        description="Auth method: client_secret_basic | shared_key_jwt | private_key_jwt",
        default=None,
    )
    client_auth_signing_alg: str | None = Field(
        description="e.g., ES256 or HS256",
        default=None,
    )
    client_secret: str | None = Field(
        description="For client_secret_basic or shared_key_jwt",
        default=None,
    )
    jwks: dict[str, Any] | None = Field(
        description="Public key for private_key_jwt",
        default=None,
    )
    jwks_uri: str | None = Field(
        description="Public key URI for private_key_jwt",
        default=None,
    )


class ClientOut(BaseModel):
    """Client onboarding response."""

    model_config = ConfigDict(from_attributes=True)

    client_id: str
    client_auth_method: str
    client_auth_signing_alg: str | None = None
    client_secret: str | None = None
    jwks: dict[str, Any] | None = None
    jwks_uri: str | None = None

    @model_validator(mode="before")
    def _prepare_data(cls, data: Any) -> dict[str, Any]:
        if isinstance(data, dict):
            secret = data.get("client_secret", None)
            data["client_secret"] = "***redacted***" if secret else None
        else:
            secret = getattr(data, "client_secret", None)
            setattr(data, "client_secret", "***redacted***" if secret else None)
        return data
