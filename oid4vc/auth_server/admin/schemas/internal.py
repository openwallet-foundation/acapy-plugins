"""Schemas for signing JWTs for tenants."""

from typing import Literal
from pydantic import BaseModel


class JwtSignRequest(BaseModel):
    """Payload for signing a JWT."""

    alg: Literal["ES256"] | None = None
    kid: str | None = None
    claims: dict
    ttl_seconds: int | None = None  # if exp not in claims


class JwtSignResponse(BaseModel):
    """Response for signing a JWT."""

    jwt: str
    kid: str
    alg: str
    exp: int


class TenantDbResponse(BaseModel):
    """Response model for tenant database connection."""

    db_url: str
    db_schema: str


class TenantJwksResponse(BaseModel):
    """Response model for tenant JWKS (JSON Web Key Set)."""

    keys: list[dict]
