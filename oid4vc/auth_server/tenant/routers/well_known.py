"""OIDC discovery and JWKS endpoints (thin router)."""

from fastapi import APIRouter, HTTPException, Path, Request, Response
from fastapi.responses import ORJSONResponse

from tenant.config import settings
from tenant.services.well_known_service import (
    build_oauth_auth_server,
    load_tenant_jwks,
)

router = APIRouter(prefix="/.well-known")


@router.get(
    "/oauth-authorization-server/tenants/{uid}",
    response_class=ORJSONResponse,
    tags=["public"],
)
async def openid_configuration(
    request: Request, response: Response, uid: str = Path(...)
):
    """Return OIDC discovery for the tenant."""
    try:
        payload = await build_oauth_auth_server(uid, request)
    except HTTPException:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    ttl = settings.CONTEXT_CACHE_TTL
    response.headers["Cache-Control"] = f"private, max-age={ttl}"
    return payload


@router.get(
    "/jwks.json/tenants/{uid}",
    response_class=ORJSONResponse,
    tags=["public"],
)
async def jwks(
    request: Request,
    response: Response,
    uid: str = Path(...),
):
    """Return JWKS (RFC 7517) for the tenant."""
    try:
        keys = await load_tenant_jwks(uid)
    except HTTPException:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    ttl = settings.CONTEXT_CACHE_TTL
    response.headers["Cache-Control"] = f"public, max-age={ttl}"
    return keys
