"""Security helpers."""

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from authlib.jose import JsonWebKey, jwt

from core.utils.json import safe_json_loads
from tenant.config import settings


def utcnow() -> datetime:
    """UTC now."""
    return datetime.now(timezone.utc)


def new_refresh_token() -> str:
    """Generate a new refresh token."""
    return secrets.token_urlsafe(settings.TOKEN_BYTES)


def hash_token(value: str) -> str:
    """Hash a token value."""
    d = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")


def compute_access_exp(now: datetime | None = None) -> datetime:
    """Compute access token expiry."""
    now = now or utcnow()
    return now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)


def compute_refresh_exp(now: datetime | None = None) -> datetime:
    """Compute refresh token expiry."""
    now = now or utcnow()
    return now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)


def b64url_decode(data: str) -> bytes:
    """Decode base64url without verification (for JWT header/payload)."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def jwt_payload_unverified(jwt_str: str) -> dict[str, Any]:
    """Return unverified JWT payload as dict (no signature check)."""
    try:
        _, payload, _ = jwt_str.split(".", 2)
        return {} if not payload else safe_json_loads(b64url_decode(payload))
    except Exception:
        return {}


def jwt_header_unverified(jwt_str: str) -> dict[str, Any]:
    """Return unverified JWT header as dict (no signature check)."""
    try:
        header, _, _ = jwt_str.split(".", 2)
        return {} if not header else safe_json_loads(b64url_decode(header))
    except Exception:
        return {}


def verify_access_jwt(token: str, jwks: dict, expected_iss: str | None = None):
    """Verify JWT signature & claims using Authlib."""
    # Provide a Key Set; Authlib will pick by 'kid' automatically
    key_set = JsonWebKey.import_key_set(jwks)

    # Optionally constrain 'iss' if you want a strict match
    claims_options = {}
    if expected_iss:
        claims_options["iss"] = {"essential": True, "values": [expected_iss]}

    claims = jwt.decode(token, key_set, claims_options=claims_options)
    # exp/nbf/iats checks
    claims.validate(now=datetime.now(timezone.utc))

    return claims
