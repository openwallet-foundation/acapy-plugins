"""Tenant token lifecycle helpers."""

import secrets
from datetime import datetime, timedelta

from core.security.utils import utcnow
from tenant.config import settings


def new_refresh_token() -> str:
    """Opaque refresh token."""
    return secrets.token_urlsafe(settings.TOKEN_BYTES)


def compute_access_exp(now: datetime | None = None) -> datetime:
    """Access token expiry from now."""
    now = now or utcnow()
    return now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)


def compute_refresh_exp(now: datetime | None = None) -> datetime:
    """Refresh token expiry from now."""
    now = now or utcnow()
    return now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)
