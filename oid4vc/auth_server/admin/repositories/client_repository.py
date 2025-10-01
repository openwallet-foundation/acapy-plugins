"""Repository for OAuth2/OIDC clients (issuer auth)."""

from typing import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import Client
from core.repositories.client_repository import ClientRepository as BaseClientRepository


class ClientRepository(BaseClientRepository):
    """Data-access for clients."""

    def __init__(self, session: AsyncSession) -> None:
        """Constructor."""
        super().__init__(session)

    async def list(self) -> Sequence[Client]:
        """List tenants."""
        result = await self.session.execute(select(Client))
        return result.scalars().all()

    async def get(self, id: int) -> Client | None:
        """Get a specific tenant by internal id."""
        result = await self.session.execute(select(Client).where(Client.id == id))
        return result.scalar_one_or_none()

    async def update_values(self, id: int, values: dict) -> int:
        """Update tenant values."""
        if not values:
            return 0
        res = await self.session.execute(
            update(Client).where(Client.id == id).values(**values)
        )
        return res.rowcount or 0

    async def delete(self, id: int) -> int:
        """Delete a tenant."""
        res = await self.session.execute(delete(Client).where(Client.id == id))
        return res.rowcount or 0
