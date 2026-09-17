"""Security helpers."""

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from joserfc import jwt
from joserfc.jws import extract_compact
from joserfc.jwk import KeySet

from core.consts import SUPPORTED_SIGNING_ALGS
from core.utils.json import safe_json_loads


def utcnow() -> datetime:
    """Current time, UTC."""
    return datetime.now(timezone.utc)


def hash_token(value: str) -> str:
    """SHA-256 of a token, base64url-encoded."""
    d = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")


def jwt_payload_unverified(jwt_str: str) -> dict[str, Any]:
    """Return unverified JWT payload as dict (no signature check)."""
    try:
        obj = extract_compact(jwt_str.encode())
        return safe_json_loads(obj.payload)
    except Exception:
        return {}


def jwt_header_unverified(jwt_str: str) -> dict[str, Any]:
    """Return unverified JWT header as dict (no signature check)."""
    try:
        obj = extract_compact(jwt_str.encode())
        return dict(obj.headers())
    except Exception:
        return {}


def verify_access_jwt(token: str, jwks: dict, expected_iss: str | None = None):
    """Verify JWT signature & claims using joserfc."""

    key_set = KeySet.import_key_set(jwks)

    result = jwt.decode(token, key_set, algorithms=list(SUPPORTED_SIGNING_ALGS))

    claims_opts = {}
    if expected_iss:
        claims_opts["iss"] = {"essential": True, "values": [expected_iss]}

    claims_registry = jwt.JWTClaimsRegistry(**claims_opts)
    claims_registry.validate(result.claims)

    return result.claims
