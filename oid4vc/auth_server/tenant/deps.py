"""Per-tenant dependencies: DB session + JWKS, cached by tenant uid via Admin API."""

import time
from functools import lru_cache
from typing import AsyncIterator

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.observability.observability import current_request_id
from core.utils.retry import with_retries
from tenant.config import settings

# In-memory cache: uid -> (timestamp, ctx)
_CACHE: dict[str, tuple[float, dict]] = {}
_TTL = settings.CONTEXT_CACHE_TTL


@with_retries(
    max_attempts=3,
    base_delay=0.2,
    max_delay=2.0,
    retry_on=(httpx.RequestError, httpx.HTTPStatusError),
    should_retry=lambda e: isinstance(e, httpx.RequestError)
    or (
        isinstance(e, httpx.HTTPStatusError)
        and getattr(e, "response", None) is not None
        and e.response.status_code >= 500
    ),
)
async def _get_admin_json(client: httpx.AsyncClient, url: str, headers: dict) -> dict:
    """GET JSON from Admin with retries on transient errors."""
    res = await client.get(url, headers=headers)
    if res.status_code >= 500:
        raise httpx.HTTPStatusError("server error", request=res.request, response=res)
    res.raise_for_status()
    return res.json()


async def _fetch_tenant_ctx(uid: str | None = None) -> dict:
    """Fetch DB and JWKS from Admin and update cache."""
    if not uid:
        raise HTTPException(status_code=400, detail="Missing tenant uid.")

    base = f"{settings.ADMIN_INTERNAL_BASE_URL}/tenants/{uid}"
    headers = {"Authorization": f"Bearer {settings.ADMIN_INTERNAL_AUTH_TOKEN}"}
    rid = current_request_id()
    if rid:
        headers["X-Request-ID"] = rid

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            db_data = await _get_admin_json(client, f"{base}/db", headers)
        except Exception as ex:
            # Fatal: cannot operate without DB coordinates for the tenant
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
    return ctx


async def _load_tenant_ctx(request: Request, force: bool = False) -> dict:
    """Resolve tenant ctx (db + jwks) from Admin and cache by TTL."""
    uid: str | None = request.path_params.get("uid")
    if not uid:
        raise HTTPException(status_code=400, detail="tenant uid missing in path")

    now = time.time()
    cached = _CACHE.get(uid)
    if not force and cached is not None:
        ts, ctx = cached
        if now - ts < _TTL:
            return ctx

    return await _fetch_tenant_ctx(uid)


async def get_tenant_ctx(uid: str, key: str) -> dict:
    """Return a specific section of the tenant ctx ("db" or "jwks")."""
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
    """Helper for `.well-known/jwks.json`."""
    jwks = await get_tenant_ctx(uid, "jwks")
    # Pass through if already spec-compliant; otherwise normalize sensibly
    if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
        return jwks
    if isinstance(jwks, list):
        return {"keys": jwks}
    return {"keys": []}


@lru_cache(maxsize=256)
def _sessionmaker_for(url: str, schema: str) -> async_sessionmaker[AsyncSession]:
    """Cache a sessionmaker per (url, schema)."""
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        connect_args={"server_settings": {"search_path": schema}},
    )
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session(
    request: Request,
    ctx: dict = Depends(_load_tenant_ctx),
) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency to inject an AsyncSession per request."""

    def open_session(db: dict) -> AsyncSession:
        sm = _sessionmaker_for(db["url"], db["schema"])  # cached by (url, schema)
        return sm()

    db = ctx["db"]
    session = open_session(db)
    try:
        try:
            await session.execute(text("SELECT 1"))
        except Exception:
            # Close the broken session and refresh ctx, then retry once
            await session.close()
            uid = request.path_params.get("uid")
            fresh = await _fetch_tenant_ctx(uid)
            session = open_session(fresh["db"])  # type: ignore[index]
            await session.execute(text("SELECT 1"))
        # Yield exactly once
        yield session
    finally:
        await session.close()
