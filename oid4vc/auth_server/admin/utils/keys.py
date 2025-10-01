"""Utilities for tenant key selection and validity checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from admin.models import TenantKey


def is_time_valid(key: TenantKey, *, now: Optional[datetime] = None) -> bool:
    """Return True if key is currently within [not_before, not_after)."""
    _now = now or datetime.now(timezone.utc)
    nb = key.not_before or _now
    na = key.not_after
    return nb <= _now and (na is None or _now < na)


def select_signing_key(
    keys: Iterable[TenantKey],
    *,
    preferred_kid: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Optional[TenantKey]:
    """Choose an active, time-valid key from an iterable."""
    _now = now or datetime.now(timezone.utc)

    if preferred_kid:
        for k in keys:
            if (
                k.kid == preferred_kid
                and k.status == "active"
                and is_time_valid(k, now=_now)
            ):
                return k

    for k in keys:
        if k.status == "active" and is_time_valid(k, now=_now):
            return k

    return None
