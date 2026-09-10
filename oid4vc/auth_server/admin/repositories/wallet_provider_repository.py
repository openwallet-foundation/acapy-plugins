"""Repository for wallet provider allow list."""

from typing import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from admin.models import WalletProvider


class WalletProviderRepository:
    """Data-access layer for the wallet_provider allow list table."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session."""
        self.session = session

    async def list(self, active_only: bool = False) -> Sequence[WalletProvider]:
        """Return all wallet providers, optionally filtered to active only."""
        stmt = select(WalletProvider)
        if active_only:
            stmt = stmt.where(WalletProvider.active.is_(True))
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get(self, id: int) -> WalletProvider | None:
        """Fetch a single wallet provider by primary key."""
        result = await self.session.execute(
            select(WalletProvider).where(WalletProvider.id == id)
        )
        return result.scalar_one_or_none()

    async def get_by_iss(self, iss: str) -> WalletProvider | None:
        """Look up a wallet provider by its issuer identifier."""
        result = await self.session.execute(
            select(WalletProvider).where(WalletProvider.iss == iss)
        )
        return result.scalar_one_or_none()

    async def update_values(self, id: int, values: dict) -> int:
        """Apply a partial update and return the number of rows affected."""
        if not values:
            return 0
        res = await self.session.execute(
            update(WalletProvider).where(WalletProvider.id == id).values(**values)
        )
        return res.rowcount or 0

    async def delete(self, id: int) -> int:
        """Delete a wallet provider by pkey and return the number of rows removed."""
        res = await self.session.execute(
            delete(WalletProvider).where(WalletProvider.id == id)
        )
        return res.rowcount or 0
