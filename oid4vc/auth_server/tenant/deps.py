"""Tenant deps: DB session + JWKS resolution, cached per uid."""

import re
import time
from collections import OrderedDict
from typing import AsyncIterator

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.cached_session import (
    _session_factory,
    dispose_cached_engines,
)
from core.observability.observability import internal_api_headers
from core.utils.retry import with_retries
from tenant.config import settings

# In-memory cache: uid -> (timestamp, ctx), LRU-bounded
_CACHE: OrderedDict[str, tuple[float, dict]] = OrderedDict()
_MAX_CACHE = 256
_TTL = settings.CONTEXT_CACHE_TTL
# Allowlist blocks / \ % and null — the only chars that enable URL path traversal
_UID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


@with_retries(
    max_attempts=3,
    base_delay=0.2,
    max_delay=2.0,
    retry_on=(httpx.RequestError, httpx.HTTPStatusError),
    should_retry=lambda e: (
        isinstance(e, httpx.RequestError)
        or (
            isinstance(e, httpx.HTTPStatusError)
            and getattr(e, "response", None) is not None
            and e.response.status_code >= 500
        )
    ),
)
async def _get_admin_json(client: httpx.AsyncClient, url: str, headers: dict) -> dict:
    """GET JSON from admin; retries configured by decorator."""
    res = await client.get(url, headers=headers)
    if res.status_code >= 500:
        raise httpx.HTTPStatusError("server error", request=res.request, response=res)
    res.raise_for_status()
    return res.json()


async def _fetch_tenant_ctx(uid: str | None = None) -> dict:
    """Fetch tenant DB + JWKS from admin, update local cache."""
    if not uid:
        raise HTTPException(status_code=400, detail="Missing tenant uid.")
    if not _UID_RE.match(uid):
        raise HTTPException(status_code=400, detail="invalid_tenant")

    base = f"{settings.INTERNAL_BASE_URL}/tenants/{uid}"
    headers = internal_api_headers(settings.INTERNAL_AUTH_TOKEN)

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            db_data = await _get_admin_json(client, f"{base}/db", headers)
        except Exception as ex:
            raise HTTPException(
                status_code=503, detail="admin_tenant_db_service_unavailable"
            ) from ex
        try:
            jwks_data = await _get_admin_json(client, f"{base}/jwks", headers)
        except Exception:
            jwks_data = {"keys": []}

    db_url, db_schema = db_data.get("db_url"), db_data.get("db_schema")
    if not db_url or not db_schema:
        raise HTTPException(status_code=500, detail="invalid tenant DB info from admin")
    if not isinstance(jwks_data, dict):
        jwks_data = {"keys": []}

    ctx = {
        "db": {"url": db_url, "schema": db_schema},
        "jwks": jwks_data,
    }
    _CACHE[uid] = (time.time(), ctx)
    _CACHE.move_to_end(uid)
    while len(_CACHE) > _MAX_CACHE:
        _CACHE.popitem(last=False)
    return ctx


async def _load_tenant_ctx(request: Request) -> dict:
    """Load tenant context from cache or fetch from admin."""
    uid: str | None = request.path_params.get("uid")
    if not uid:
        raise HTTPException(status_code=400, detail="tenant uid missing in path")

    now = time.time()
    cached = _CACHE.get(uid)
    if cached is not None:
        ts, ctx = cached
        if now - ts < _TTL:
            return ctx

    return await _fetch_tenant_ctx(uid)


async def get_tenant_ctx(uid: str, key: str) -> dict:
    """Get a section of tenant context by key."""
    now = time.time()
    cached = _CACHE.get(uid)
    if cached is not None:
        ts, ctx = cached
        if now - ts < _TTL:
            section = ctx.get(key) if isinstance(ctx, dict) else None
            if isinstance(section, dict):
                return section
    # refetch
    ctx = await _fetch_tenant_ctx(uid)
    section = ctx.get(key) if isinstance(ctx, dict) else None
    if isinstance(section, dict):
        return section
    return {}


async def get_tenant_jwks(uid: str) -> dict:
    """Return normalized JWKS for a tenant."""
    jwks = await get_tenant_ctx(uid, "jwks")
    # Pass through if already spec-compliant; otherwise normalize sensibly
    if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
        return jwks
    if isinstance(jwks, list):
        return {"keys": jwks}
    return {"keys": []}


_MAX_ENGINES = 128


def _sessionmaker_for(url: str, schema: str):
    """Delegate to shared engine cache with tenant-sized limit."""
    return _session_factory(url, schema, max_engines=_MAX_ENGINES)


async def dispose_engines() -> None:
    """Shutdown hook — dispose pooled engines."""
    await dispose_cached_engines()


async def get_db_session(
    request: Request,
    ctx: dict = Depends(_load_tenant_ctx),
) -> AsyncIterator[AsyncSession]:
    """Yield a per-request async DB session for the tenant."""

    def open_session(db: dict) -> AsyncSession:
        return _sessionmaker_for(db["url"], db["schema"])()

    db = ctx["db"]
    session = open_session(db)
    try:
        try:
            await session.execute(text("SELECT 1"))
        except Exception:
            # Stale connection — refresh ctx and retry once
            await session.close()
            uid = request.path_params.get("uid")
            fresh = await _fetch_tenant_ctx(uid)
            session = open_session(fresh["db"])  # type: ignore[index]
            await session.execute(text("SELECT 1"))
        # Yield exactly once
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
