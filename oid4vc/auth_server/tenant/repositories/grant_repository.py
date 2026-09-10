"""Pre-authorized grant repository."""

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.models import PreAuthCode


class GrantRepository:
    """Repository for pre-authorized code grants."""

    def __init__(self, db: AsyncSession):
        """Constructor."""
        self.db = db

    async def get_by_code(self, code: str) -> PreAuthCode | None:
        """Fetch PAC by code, eagerly loading subject."""
        stmt = select(PreAuthCode).where(PreAuthCode.code == code)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def mark_used(self, pac: PreAuthCode) -> bool:
        """Mark PAC used if previously unused; return True if updated."""
        stmt = (
            update(PreAuthCode)
            .where(PreAuthCode.id == pac.id, PreAuthCode.used.is_(False))
            .values(used=True)
        )
        res = await self.db.execute(stmt)
        return bool(res.rowcount and res.rowcount > 0)

    async def consume_valid(self, pac_id: int, now) -> bool:
        """Atomically consume PAC if unexpired and unused; return True if consumed."""
        stmt = (
            update(PreAuthCode)
            .where(
                PreAuthCode.id == pac_id,
                PreAuthCode.used.is_(False),
                PreAuthCode.expires_at > now,
            )
            .values(used=True)
        )
        res = await self.db.execute(stmt)
        return bool(res.rowcount and res.rowcount > 0)

    async def increment_tx_code_attempts(self, pac_id: int, max_attempts: int) -> int:
        """Bump attempt counter; burns the code if limit hit. Returns new count."""
        stmt = (
            update(PreAuthCode)
            .where(
                PreAuthCode.id == pac_id,
                PreAuthCode.used.is_(False),
            )
            .values(tx_code_attempts=PreAuthCode.tx_code_attempts + 1)
            .returning(PreAuthCode.tx_code_attempts)
        )
        res = await self.db.execute(stmt)
        new_count = res.scalar_one_or_none()
        if new_count is None:
            return max_attempts  # already consumed
        if new_count >= max_attempts:
            consume_stmt = (
                update(PreAuthCode)
                .where(PreAuthCode.id == pac_id, PreAuthCode.used.is_(False))
                .values(used=True)
            )
            await self.db.execute(consume_stmt)
        return new_count

    async def create_pre_auth_code(
        self,
        *,
        subject_id: int,
        code: str,
        tx_code: str | None,
        authorization_details: list[dict[str, Any]] | None,
        issued_at,
        expires_at,
    ) -> PreAuthCode:
        """Create a pre-authorized code grant."""
        pac = PreAuthCode(
            subject_id=subject_id,
            code=code,
            tx_code=tx_code,
            authorization_details=authorization_details,
            issued_at=issued_at,
            expires_at=expires_at,
            used=False,
        )
        self.db.add(pac)
        await self.db.flush()
        return pac
