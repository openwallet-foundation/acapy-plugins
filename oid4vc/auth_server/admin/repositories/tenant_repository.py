"""Data-access layer for tenants."""

from typing import Sequence
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from admin.models import Tenant


class TenantRepository:
    """Data-access layer for tenants."""

    def __init__(self, session: AsyncSession) -> None:
        """Constructor."""
        self.session = session

    async def list(self) -> Sequence[Tenant]:
        """List tenants."""
        result = await self.session.execute(select(Tenant))
        return result.scalars().all()

    async def get(self, id: int) -> Tenant | None:
        """Get a specific tenant by internal id."""
        result = await self.session.execute(select(Tenant).where(Tenant.id == id))
        return result.scalar_one_or_none()

    async def get_by_uid(self, uid: str) -> Tenant | None:
        """Get a specific tenant by external uid (UUID)."""
        result = await self.session.execute(select(Tenant).where(Tenant.uid == uid))
        return result.scalar_one_or_none()

    async def exists(self, id: int) -> bool:
        """Check if a tenant exists."""
        return (await self.get(id)) is not None

    async def update_values(self, id: int, values: dict) -> int:
        """Update tenant values."""
        if not values:
            return 0
        res = await self.session.execute(
            update(Tenant).where(Tenant.id == id).values(**values)
        )
        return res.rowcount or 0

    async def delete(self, id: int) -> int:
        """Delete a tenant."""
        res = await self.session.execute(delete(Tenant).where(Tenant.id == id))
        return res.rowcount or 0

    async def exists_by_uid(self, uid: str) -> bool:
        """Check if tenant with uid or name exists."""
        result = await self.session.execute(select(Tenant).where(Tenant.uid == uid))
        return result.scalar_one_or_none() is not None
