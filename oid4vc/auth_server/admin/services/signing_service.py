"""JWT signing service."""

from datetime import datetime, timezone

from authlib.jose import JsonWebKey, jwt
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.models import Tenant, TenantKey
from admin.schemas.internal import JwtSignRequest, JwtSignResponse
from admin.utils.crypto import decrypt_private_pem
from admin.utils.keys import select_signing_key

MAX_TTL_SECONDS = 3600


async def sign_tenant_jwt(
    session: AsyncSession, uid: str, req: JwtSignRequest
) -> JwtSignResponse:
    """Sign a JWT for tenant `uid`. Requires integer `exp`; sets `iat` if missing."""
    # Choose a key: explicit kid first, else most recent active/retiring
    stmt = (
        select(TenantKey)
        .join(Tenant, Tenant.id == TenantKey.tenant_id)
        .where(Tenant.uid == uid)
        .order_by(TenantKey.not_before.desc(), TenantKey.created_at.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()

    now = datetime.now(timezone.utc)

    # Choose a key using shared utility (ordered by not_before desc, created_at desc)
    key = select_signing_key(rows, preferred_kid=req.kid, now=now)
    if not key:
        raise HTTPException(status_code=404, detail="signing_key_not_found")

    alg = req.alg or key.alg
    if alg != "ES256":
        raise HTTPException(status_code=400, detail="unsupported_alg")

    # Claims validation
    now_ts = int(now.timestamp())

    if getattr(req, "ttl_seconds", None) is not None:
        # We require callers to provide explicit exp for auditability.
        raise HTTPException(status_code=400, detail="use_exp_not_ttl")

    claims: dict = dict(req.claims or {})

    exp_val = claims.get("exp")
    if not isinstance(exp_val, int):
        raise HTTPException(status_code=400, detail="claims_missing_or_invalid_exp")

    if "iat" not in claims:
        claims["iat"] = now_ts

    if exp_val <= now_ts:
        raise HTTPException(status_code=400, detail="exp_in_past")
    if exp_val - now_ts > MAX_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="exp_exceeds_max_ttl")

    # Ensure tokens do not outlive the key
    if key.not_after is not None and exp_val > int(key.not_after.timestamp()):
        raise HTTPException(status_code=400, detail="exp_exceeds_key_validity")

    # Sign
    pem = decrypt_private_pem(key.private_pem_enc)  # type: ignore
    jwk_key = JsonWebKey.import_key(pem)  # type: ignore
    header = {"alg": alg, "kid": key.kid, "typ": "JWT"}
    token = jwt.encode(header, claims, jwk_key).decode()

    return JwtSignResponse(jwt=token, kid=key.kid, alg=alg, exp=exp_val)
