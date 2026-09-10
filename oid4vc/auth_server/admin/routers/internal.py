"""API for tenant SERVICE helpers: DB info, JWKS, JWT signing, wallet provider lookup."""

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.schemas.internal import (
    JwtSignRequest,
    JwtSignResponse,
    TenantDbResponse,
    TenantJwksResponse,
)
from admin.security.bearer import require_internal_auth
from admin.services.internal_service import (
    get_tenant_db,
    get_tenant_jwks,
    lookup_wallet_provider,
)
from admin.services.signing_service import sign_tenant_jwt

router = APIRouter(dependencies=[Depends(require_internal_auth)])


@router.get("/tenants/{uid}/db", response_model=TenantDbResponse)
async def get_db(
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Return tenant DB connect URL and schema."""
    return await get_tenant_db(db, uid)


@router.get("/tenants/{uid}/jwks", response_model=TenantJwksResponse)
async def get_jwks(
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Return public JWKS for the tenant."""
    return await get_tenant_jwks(db, uid)


@router.post(
    "/tenants/{uid}/jwts",
    response_model=JwtSignResponse,
    response_model_exclude_none=True,
)
async def sign_jwt(
    body: JwtSignRequest,
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Sign a JWT for the tenant."""
    return await sign_tenant_jwt(db, uid, body)


@router.get("/wallet-providers/lookup")
async def wallet_provider_lookup(
    iss: str = Query(...),
    kid: str | None = Query(None),
    db: AsyncSession = Depends(get_db_session),
):
    """Look up a wallet provider key by iss + optional kid from cache."""
    result = await lookup_wallet_provider(db, iss, kid)
    if not result:
        return {"found": False}
    return {"found": True, **result}
