"""Wallet provider schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class WalletProviderIn(BaseModel):
    """Create input."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "iss": "https://wallet.example.com",
                "jwks": {
                    "keys": [
                        {
                            "kid": "wallet-example-key-1",
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                        }
                    ]
                },
                "name": "Example Wallet Provider",
                "active": True,
            }
        }
    )

    iss: str = Field(description="Wallet provider issuer identifier (URL)")
    jwks: dict[str, Any] | None = Field(default=None, description="Inline JWKS document")
    jwks_uri: str | None = Field(
        default=None, description="URL to fetch the provider's JWKS"
    )
    name: str | None = Field(default=None, description="Display name for the provider")
    active: bool = Field(default=True, description="Whether this provider is active")

    @model_validator(mode="after")
    def _require_jwks_or_uri(self):
        if not self.jwks and not self.jwks_uri:
            raise ValueError("Either jwks or jwks_uri must be provided")
        return self


class WalletProviderUpdate(BaseModel):
    """Partial update input."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Example Wallet Provider (v2)",
                "active": False,
            }
        }
    )

    iss: str | None = Field(default=None, description="Updated issuer identifier")
    jwks: dict[str, Any] | None = Field(
        default=None, description="Updated inline JWKS document"
    )
    jwks_uri: str | None = Field(default=None, description="Updated JWKS URI")
    name: str | None = Field(default=None, description="Updated display name")
    active: bool | None = Field(default=None, description="Updated active status")


class WalletProviderOut(BaseModel):
    """API response."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "iss": "https://wallet.example.com",
                "jwks": {
                    "keys": [
                        {
                            "kid": "wallet-example-key-1",
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                        }
                    ]
                },
                "name": "Example Wallet Provider",
                "active": True,
                "created_at": "2026-04-27T14:30:00",
                "updated_at": None,
            }
        },
    )

    id: int
    iss: str
    jwks: dict[str, Any] | None = None
    jwks_uri: str | None = None
    name: str | None = None
    active: bool
    created_at: datetime
    updated_at: datetime | None = None
