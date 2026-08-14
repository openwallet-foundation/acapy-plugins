"""Internal API schemas."""

from typing import Literal
from pydantic import BaseModel


class JwtSignRequest(BaseModel):
    """JWT signing input."""

    alg: Literal["ES256", "ES384", "EdDSA"] | None = None
    kid: str | None = None
    claims: dict
    ttl_seconds: int | None = None  # if exp not in claims


class JwtSignResponse(BaseModel):
    """Signed JWT output."""

    jwt: str
    kid: str
    alg: str
    exp: int


class TenantDbResponse(BaseModel):
    """Tenant DB coordinates."""

    db_url: str
    db_schema: str


class TenantJwksResponse(BaseModel):
    """Tenant public keyset."""

    keys: list[dict]
