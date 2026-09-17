"""INTERNAL helpers: DB info, JWKS, JWT signing."""

from typing import Dict, List
from datetime import datetime, timezone, timedelta

from joserfc import jwk
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.config import settings
from admin.models import Tenant, TenantKey, WalletProvider
from admin.utils.db_utils import resolve_tenant_urls
from admin.utils.keys import is_time_valid
from core.security.jwks_cache import JWKSCache
from core.utils.logging import get_logger

logger = get_logger(__name__)

MAX_TTL_SECONDS = 3600

# Cache for wallet provider JWKS (keyed by iss)
_provider_jwks_cache = JWKSCache(ttl=300)


async def load_wallet_providers(session: AsyncSession) -> None:
    """Load all active wallet providers into the JWKS cache (startup)."""
    rows = (
        (
            await session.execute(
                select(WalletProvider).where(WalletProvider.active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        _provider_jwks_cache.put(
            row.iss,
            row.jwks,
            jwks_uri=row.jwks_uri,
        )
    logger.info("Loaded %d wallet providers into cache", len(rows))


def refresh_provider_cache(iss: str, jwks: dict | None, jwks_uri: str | None) -> None:
    """Refresh a single provider's cache entry (called after create/update)."""
    _provider_jwks_cache.put(iss, jwks, jwks_uri=jwks_uri)


def invalidate_provider_cache(iss: str) -> None:
    """Remove a provider from cache (called after delete/deactivate)."""
    _provider_jwks_cache.invalidate(iss)


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
        jwk_obj = jwk.import_key(row.public_jwk)
        jwk_dict = jwk_obj.as_dict(private=False, kid=row.kid, alg=row.alg, use="sig")
        if jwk_dict is not None:
            keys.append(jwk_dict)
    return {"keys": keys}


async def _revalidate_provider(session: AsyncSession, iss: str) -> bool:
    """Re-read a provider from the DB when its cache entry is missing or stale.

    Keeps deactivations visible to every worker process, not just the one that
    served the write.
    """
    if not _provider_jwks_cache.is_stale(iss):
        return True

    row = (
        await session.execute(select(WalletProvider).where(WalletProvider.iss == iss))
    ).scalar_one_or_none()
    if not row or not row.active:
        _provider_jwks_cache.invalidate(iss)
        return False

    _provider_jwks_cache.put(row.iss, row.jwks, jwks_uri=row.jwks_uri)
    return True


async def lookup_wallet_provider(
    session: AsyncSession, iss: str, kid: str | None = None
) -> dict | None:
    """Look up wallet provider key(s) by iss (+ optional kid).

    When *kid* is provided, returns a single key dict under ``public_key``.
    When *kid* is omitted, returns all cached keys under ``keys``.
    """
    if not await _revalidate_provider(session, iss):
        logger.info("No active wallet provider for %s", iss)
        return None

    if kid:
        key = await _provider_jwks_cache.get_key(iss, kid)
        if key:
            return {"iss": iss, "public_key": key.as_dict(private=False)}
        logger.info("kid %r not found for provider %s", kid, iss)
        return None

    # No kid — return full keyset for trial verification
    key_set = _provider_jwks_cache.get_keyset(iss)
    if not key_set or not key_set.keys:
        logger.info("No keys cached for provider %s", iss)
        return None
    return {
        "iss": iss,
        "keys": [k.as_dict(private=False) for k in key_set.keys],
    }
