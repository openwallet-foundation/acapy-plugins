"""JTI replay prevention (PostgreSQL-backed).

Covers: private_key_jwt (RFC 7523), attestation PoP (draft-07).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.dialects.postgresql import insert

from tenant.models import JtiSeen

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class JtiCache:
    """INSERT ON CONFLICT dedup for JTI values."""

    def __init__(self, *, window: int | float = 300):
        """Window = default expiry if caller doesn't provide one."""
        self._window = window

    async def check_and_store(
        self,
        jti: str | None,
        db: AsyncSession,
        now: float | None = None,
        expires_at: float | None = None,
        metadata: dict | None = None,
    ) -> bool:
        """Return True if fresh (stored); False if missing or replayed."""
        if not jti:
            return False
        if now is None:
            now = time.time()

        exp_ts = expires_at if expires_at is not None else now + self._window
        exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
        now_dt = datetime.fromtimestamp(now, tz=timezone.utc)

        # Conflict update only fires if existing row is already expired.
        stmt = (
            insert(JtiSeen)
            .values(jti=jti, expires_at=exp_dt, jti_metadata=metadata)
            .on_conflict_do_update(
                index_elements=[JtiSeen.jti],
                set_={
                    JtiSeen.expires_at: exp_dt,
                    JtiSeen.jti_metadata: metadata,
                },
                where=JtiSeen.expires_at <= now_dt,
            )
            .returning(JtiSeen.jti)
        )
        result = await db.execute(stmt)
        row = result.first()
        return row is not None
