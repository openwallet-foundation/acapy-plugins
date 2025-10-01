"""OIDC discovery and JWKS endpoints (thin router)."""

from fastapi import APIRouter, Path, Request, Response
from fastapi.responses import ORJSONResponse

from tenant.config import settings
from tenant.services.well_known_service import (
    build_openid_configuration,
    load_tenant_jwks,
)

router = APIRouter(prefix="/tenants/{uid}")


@router.get(
    "/.well-known/openid-configuration",
    response_class=ORJSONResponse,
    tags=["public"],
)
async def openid_configuration(
    request: Request, response: Response, uid: str = Path(...)
):
    """Return OIDC discovery for the tenant."""
    payload = build_openid_configuration(uid, request)
    ttl = settings.CONTEXT_CACHE_TTL
    response.headers["Cache-Control"] = f"public, max-age={ttl}"
    return payload


@router.get(
    "/.well-known/jwks.json",
    response_class=ORJSONResponse,
    tags=["public"],
)
async def jwks(
    request: Request,
    response: Response,
    uid: str = Path(...),
):
    """Return JWKS (RFC 7517) for the tenant."""
    keys = await load_tenant_jwks(uid)
    ttl = settings.CONTEXT_CACHE_TTL
    response.headers["Cache-Control"] = f"public, max-age={ttl}"
    return keys
