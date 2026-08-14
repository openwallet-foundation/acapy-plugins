"""Bearer auth dependencies for Admin API (router-level guards)."""

import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from admin.config import settings


_security = HTTPBearer(auto_error=False)


def _bearer_guard(settings_attr: str):
    """Create a bearer token dependency checking against a settings value."""

    def _guard(
        credentials: HTTPAuthorizationCredentials | None = Depends(_security),
    ) -> bool:
        token = credentials.credentials if credentials else ""
        expected = getattr(settings, settings_attr, "")
        if not token or not expected or not secrets.compare_digest(token, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return True

    return _guard


require_internal_auth = _bearer_guard("INTERNAL_AUTH_TOKEN")
require_admin_auth = _bearer_guard("MANAGE_AUTH_TOKEN")
