"""Repository for OAuth2/OIDC clients (issuer auth)."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import Client


class ClientRepository:
    """Data-access for clients."""

    def __init__(self, session: AsyncSession) -> None:
        """Constructor."""
        self.session = session

    async def get_by_client_id(self, client_id: str) -> Client | None:
        """Get client by client_id."""
        res = await self.session.execute(
            select(Client).where(Client.client_id == client_id)
        )
        return res.scalar_one_or_none()
