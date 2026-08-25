"""Token introspection service."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from core.security.utils import utcnow
from tenant.repositories.access_token_repository import AccessTokenRepository

_INACTIVE: dict[str, Any] = {"active": False}


async def introspect_access_token(
    db: AsyncSession, tenant_uid: str, token_str: str
) -> dict[str, Any]:
    """Introspect an access token for a tenant."""
    repo = AccessTokenRepository(db)

    token = await repo.get_by_token(token_str)

    # Evaluate all conditions regardless of outcome to normalize timing
    active = token is not None
    if active:
        active = not token.revoked
    if active:
        active = token.expires_at is not None and token.expires_at > utcnow()
    if active:
        active = bool(token.subject and token.subject.uid)
    if active:
        meta = token.token_metadata or {}
        active = meta.get("realm") == tenant_uid
    else:
        meta = {}

    if not active:
        return _INACTIVE

    token_type = meta.get("token_type") or "Bearer"
    resp: dict[str, Any] = {
        "active": True,
        "token_type": token_type,
        "sub": token.subject.uid,
        "exp": int(token.expires_at.timestamp()),
        "iat": int(token.issued_at.timestamp()),
        "realm": meta.get("realm"),
    }
    if token.cnf_jkt:
        resp["cnf"] = {"jkt": token.cnf_jkt}
    if meta.get("iss"):
        resp["iss"] = meta.get("iss")
    if meta.get("authorization_details"):
        resp["authorization_details"] = meta.get("authorization_details")
    if meta.get("amr"):
        resp["amr"] = meta.get("amr")
    if meta.get("attestation"):
        resp["attestation"] = meta.get("attestation")
    if meta.get("scope"):
        resp["scope"] = meta.get("scope")
    if meta.get("c_nonce"):
        resp["c_nonce"] = meta.get("c_nonce")
    if meta.get("c_nonce_expires_in"):
        resp["c_nonce_expires_in"] = meta.get("c_nonce_expires_in")

    return resp
