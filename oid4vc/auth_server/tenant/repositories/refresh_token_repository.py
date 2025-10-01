"""RefreshToken repository."""

from datetime import datetime, timezone
from typing import Union

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.models import RefreshToken


class RefreshTokenRepository:
    """Repository for refresh tokens."""

    def __init__(self, db: AsyncSession):
        """Constructor."""
        self.db = db

    @staticmethod
    def _to_dt(value: Union[int, float, datetime]) -> datetime:
        if isinstance(value, datetime):
            return (
                value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            )
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    async def create(
        self,
        subject_id: int,
        access_token_id: int,
        token_hash: str,
        issued_at: Union[int, float, datetime],
        expires_at: Union[int, float, datetime],
        token_metadata: dict | None = None,
    ) -> RefreshToken:
        """Create and add a new refresh token."""
        issued_dt = self._to_dt(issued_at)
        expires_dt = self._to_dt(expires_at)
        refresh_token = RefreshToken(
            subject_id=subject_id,
            access_token_id=access_token_id,
            token_hash=token_hash,
            issued_at=issued_dt,
            expires_at=expires_dt,
            token_metadata=token_metadata or {},
        )
        self.db.add(refresh_token)
        await self.db.flush()
        return refresh_token

    async def consume_valid(self, token_hash: str, now) -> tuple[int, int] | None:
        """Mark a refresh token as used if still valid."""
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.expires_at > now,
                RefreshToken.used.is_(False),
                RefreshToken.revoked.is_(False),
            )
            .values(used=True)
            .returning(RefreshToken.subject_id, RefreshToken.access_token_id)
        )
        res = await self.db.execute(stmt)
        row = res.first()
        return tuple(row) if row is not None else None
