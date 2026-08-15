"""Base repository for token models with shared behavior."""

from datetime import datetime, timezone
from typing import Any, Union

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession


class BaseTokenRepository:
    """Base for token repositories that have subject_id + revoked columns."""

    _model: Any = None  # Subclasses set this to their SQLAlchemy model

    def __init__(self, db: AsyncSession):
        """Constructor."""
        self.db = db

    @staticmethod
    def _to_dt(value: Union[int, float, datetime]) -> datetime:
        """Normalize epoch seconds or datetime to UTC datetime."""
        if isinstance(value, datetime):
            return (
                value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            )
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    async def revoke_all_for_subject(self, subject_id: int) -> int:
        """Revoke all tokens for a subject (breach response)."""
        model = self._model
        stmt = (
            update(model)
            .where(
                model.subject_id == subject_id,
                model.revoked.is_(False),
            )
            .values(revoked=True)
        )
        res = await self.db.execute(stmt)
        return res.rowcount
