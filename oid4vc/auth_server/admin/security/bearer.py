"""Bearer auth dependencies for Admin API (router-level guards)."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from admin.config import settings


_security = HTTPBearer(auto_error=False)


def require_interal_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> bool:
    """Validate internal routes via Bearer from settings."""
    token = credentials.credentials if credentials else ""
    expected = getattr(settings, "INTERNAL_AUTH_TOKEN", "")
    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def require_admin_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> bool:
    """Validate admin routes via Bearer (swap to OIDC later)."""
    token = credentials.credentials if credentials else ""
    expected = getattr(settings, "MANAGE_AUTH_TOKEN", "")
    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True
