"""Data-access layer for tenant keys."""

from sqlalchemy.ext.asyncio import AsyncSession

from admin.models import TenantKey


class TenantKeyRepository:
    """Data-access for signing keys."""

    def __init__(self, session: AsyncSession) -> None:
        """Constructor."""
        self.session = session

    async def add(self, key: TenantKey) -> None:
        """Add a key."""
        self.session.add(key)

    async def update_status(self, tenant_id: int, kid: str, status: str) -> int:
        """Update key status for a tenant key; returns number of rows changed."""
        from datetime import datetime, timezone

        from sqlalchemy import update

        stmt = (
            update(TenantKey)
            .where(TenantKey.tenant_id == tenant_id, TenantKey.kid == kid)
            .values(status=status, updated_at=datetime.now(timezone.utc))
        )
        res = await self.session.execute(stmt)
        return res.rowcount or 0
