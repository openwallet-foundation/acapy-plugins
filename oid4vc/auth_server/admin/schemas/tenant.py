"""Schemas for tenants."""

from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class TenantIn(BaseModel):
    """Tenant create payload."""

    uid: str | None = None
    name: str | None = None
    active: bool | None = None
    notes: str | None = None


class TenantOut(BaseModel):
    """Tenant response payload."""

    id: int
    uid: str
    name: str | None = None
    active: bool
    created_at: datetime
    updated_at: datetime
    notes: str | None = None

    model_config = ConfigDict(from_attributes=True)


class KeyGenIn(BaseModel):
    """Key generation payload."""

    kid: str | None = Field(
        default=None, description="Key ID; if omitted, generated automatically"
    )
    alg: str = Field(
        default="ES256", description="Signing algorithm; only ES256 supported now"
    )
    not_before: datetime | None = None
    not_after: datetime | None = None
    status: str = Field(default="active", description="active | retired | revoked")


class KeyStatusIn(BaseModel):
    """Key status update payload."""

    status: str = Field(description="active | retired | revoked")
