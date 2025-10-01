"""Token introspection service."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from core.security.utils import utcnow
from tenant.repositories.access_token_repository import AccessTokenRepository


async def introspect_access_token(
    db: AsyncSession, tenant_uid: str, token_str: str
) -> dict[str, Any]:
    """Introspect an access token for a tenant."""
    repo = AccessTokenRepository(db)

    token = await repo.get_by_token(token_str)
    if token is None:
        return {"active": False}

    if token.revoked or token.expires_at is None or token.expires_at <= utcnow():
        return {"active": False}

    if not token.subject or not token.subject.uid:
        return {"active": False}

    meta = token.token_metadata or {}
    realm = meta.get("realm")
    if realm is not None and realm != tenant_uid:
        return {"active": False}

    token_type = meta.get("token_type") or ("DPoP" if token.cnf_jkt else "Bearer")
    resp: dict[str, Any] = {
        "active": True,
        "token_type": token_type,
        "sub": token.subject.uid,
        "exp": int(token.expires_at.timestamp()),
        "iat": int(token.issued_at.timestamp()),
        "realm": realm,
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
