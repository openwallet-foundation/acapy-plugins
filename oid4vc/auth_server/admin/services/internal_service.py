"""INTERNAL helpers: DB info, JWKS, JWT signing."""

from typing import Dict, List
from datetime import datetime, timezone, timedelta

from authlib.jose import JsonWebKey
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.config import settings
from admin.models import Tenant, TenantKey
from admin.utils.db_utils import resolve_tenant_urls
from admin.utils.keys import is_time_valid

MAX_TTL_SECONDS = 3600


async def get_tenant_db(session: AsyncSession, uid: str) -> Dict[str, str]:
    """Return tenant DB URL and schema."""
    tenant_row = (
        await session.execute(select(Tenant).where(Tenant.uid == uid))
    ).scalar_one_or_none()
    if not tenant_row or not tenant_row.active:
        raise HTTPException(status_code=404, detail="tenant_not_found_or_inactive")

    async_url, _sync_url, schema = resolve_tenant_urls(tenant_row)
    return {"db_url": async_url, "db_schema": schema}


async def get_tenant_jwks(session: AsyncSession, uid: str) -> Dict[str, List[dict]]:
    """Return public JWKs for active/retiring keys."""
    stmt = (
        select(TenantKey)
        .join(Tenant, Tenant.id == TenantKey.tenant_id)
        .where(Tenant.uid == uid)
        .order_by(TenantKey.not_before.desc(), TenantKey.created_at.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    if not rows:
        return {"keys": []}

    now = datetime.now(timezone.utc)
    grace = timedelta(seconds=getattr(settings, "KEY_VERIFY_GRACE_TTL", 0) or 0)

    def _include(row: TenantKey) -> bool:
        status = str(row.status).lower()
        if status == "revoked":
            return False
        if status == "active":
            if is_time_valid(row, now=now):
                return True
            return row.not_after is not None and now < (row.not_after + grace)
        if status == "retired":
            retired_at = row.updated_at or row.created_at
            return retired_at is not None and now < (retired_at + grace)
        return False

    keys: List[dict] = []
    for row in rows:
        if not row.public_jwk or not _include(row):
            continue
        jwk_obj = JsonWebKey.import_key(row.public_jwk)
        jwk_dict = jwk_obj.as_dict(is_private=False, kid=row.kid, alg=row.alg, use="sig")
        if jwk_dict is not None:
            keys.append(jwk_dict)
    return {"keys": keys}
