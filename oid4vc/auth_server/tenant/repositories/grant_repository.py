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

    async def create_pre_auth_code(
        self,
        *,
        subject_id: int,
        code: str,
        user_pin: str | None,
        user_pin_required: bool,
        authorization_details: list[dict[str, Any]] | None,
        issued_at,
        expires_at,
    ) -> PreAuthCode:
        """Create a pre-authorized code grant."""
        pac = PreAuthCode(
            subject_id=subject_id,
            code=code,
            user_pin=user_pin,
            user_pin_required=user_pin_required,
            authorization_details=authorization_details,
            issued_at=issued_at,
            expires_at=expires_at,
            used=False,
        )
        self.db.add(pac)
        await self.db.flush()
        return pac
