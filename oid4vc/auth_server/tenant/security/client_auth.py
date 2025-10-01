"""Tenant client authentication dependency."""

from fastapi import Depends, Request, Security
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import Client as AuthClient
from core.security.client_auth import base_client_auth
from tenant.deps import get_db_session

basic_security = HTTPBasic(auto_error=False)
bearer_security = HTTPBearer(auto_error=False)


async def client_auth(
    request: Request,
    basic_creds: HTTPBasicCredentials | None = Security(basic_security),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_security),
    db: AsyncSession = Depends(get_db_session),
) -> AuthClient:
    """Authenticate client and return the persisted Client model for tenant context."""

    return await base_client_auth(db, request, basic_creds, credentials)
