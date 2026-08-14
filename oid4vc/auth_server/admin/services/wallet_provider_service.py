"""Wallet provider service."""

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.models import WalletProvider
from admin.repositories.wallet_provider_repository import WalletProviderRepository
from admin.schemas.wallet_provider import WalletProviderIn, WalletProviderUpdate
from admin.services.internal_service import (
    invalidate_provider_cache,
    refresh_provider_cache,
)


class WalletProviderService:
    """Wallet provider CRUD."""

    def __init__(self, session: AsyncSession):
        """Bind to session."""
        self.session = session
        self.repo = WalletProviderRepository(session)

    async def create(self, data: WalletProviderIn) -> WalletProvider:
        """Create a new wallet provider. Raises 409 if iss already exists."""
        existing = await self.repo.get_by_iss(data.iss)
        if existing:
            raise HTTPException(
                status_code=409,
                detail="wallet_provider_exists",
            )

        provider = WalletProvider(
            iss=data.iss,
            jwks=data.jwks,
            jwks_uri=data.jwks_uri,
            name=data.name,
            active=data.active,
        )
        self.session.add(provider)
        await self.session.commit()
        await self.session.refresh(provider)
        refresh_provider_cache(provider.iss, provider.jwks, provider.jwks_uri)
        return provider

    async def list(self, active_only: bool = False) -> list[WalletProvider]:
        """Return all wallet providers, optionally filtered to active only."""
        rows = await self.repo.list(active_only=active_only)
        return list(rows)

    async def get(self, provider_id: int) -> WalletProvider:
        """Fetch a single wallet provider by ID. Raises 404 if not found."""
        row = await self.repo.get(provider_id)
        if not row:
            raise HTTPException(status_code=404, detail="wallet_provider_not_found")
        return row

    async def update(
        self, provider_id: int, data: WalletProviderUpdate
    ) -> WalletProvider:
        """Partially update a wallet provider. Raises 404 if not found."""
        row = await self.repo.get(provider_id)
        if not row:
            raise HTTPException(status_code=404, detail="wallet_provider_not_found")

        old_iss = row.iss
        values = data.model_dump(exclude_none=True)
        if values:
            await self.repo.update_values(provider_id, values)
            await self.session.commit()
            await self.session.refresh(row)
        if old_iss != row.iss:
            invalidate_provider_cache(old_iss)
        if row.active:
            refresh_provider_cache(row.iss, row.jwks, row.jwks_uri)
        else:
            invalidate_provider_cache(row.iss)
        return row

    async def delete(self, provider_id: int) -> None:
        """Delete a wallet provider by ID. Raises 404 if not found."""
        row = await self.repo.get(provider_id)
        if not row:
            raise HTTPException(status_code=404, detail="wallet_provider_not_found")
        invalidate_provider_cache(row.iss)
        await self.repo.delete(provider_id)
        await self.session.commit()

    async def lookup(self, iss: str) -> WalletProvider | None:
        """Look up an active provider by iss (for attestation verification)."""
        row = await self.repo.get_by_iss(iss)
        if row and row.active:
            return row
        return None
