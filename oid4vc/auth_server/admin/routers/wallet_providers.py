"""Admin CRUD endpoints for trusted wallet providers."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.schemas.wallet_provider import (
    WalletProviderIn,
    WalletProviderOut,
    WalletProviderUpdate,
)
from admin.security.bearer import require_admin_auth
from admin.services.wallet_provider_service import WalletProviderService

router = APIRouter(dependencies=[Depends(require_admin_auth)])


@router.get("/wallet-providers", response_model=list[WalletProviderOut])
async def list_wallet_providers(
    active_only: bool = Query(False),
    db: AsyncSession = Depends(get_db_session),
):
    """List all trusted wallet providers, with optional active-only filter."""
    svc = WalletProviderService(db)
    rows = await svc.list(active_only=active_only)
    return [WalletProviderOut.model_validate(r) for r in rows]


@router.post("/wallet-providers", response_model=WalletProviderOut, status_code=201)
async def create_wallet_provider(
    body: WalletProviderIn,
    db: AsyncSession = Depends(get_db_session),
):
    """Register a new trusted wallet provider."""
    row = await WalletProviderService(db).create(body)
    return WalletProviderOut.model_validate(row)


@router.get("/wallet-providers/{provider_id}", response_model=WalletProviderOut)
async def get_wallet_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve a single wallet provider by ID."""
    row = await WalletProviderService(db).get(provider_id)
    return WalletProviderOut.model_validate(row)


@router.patch("/wallet-providers/{provider_id}", response_model=WalletProviderOut)
async def update_wallet_provider(
    provider_id: int,
    body: WalletProviderUpdate,
    db: AsyncSession = Depends(get_db_session),
):
    """Partially update a wallet provider (e.g. rotate key or deactivate)."""
    row = await WalletProviderService(db).update(provider_id, body)
    return WalletProviderOut.model_validate(row)


@router.delete("/wallet-providers/{provider_id}", status_code=204)
async def delete_wallet_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db_session),
):
    """Remove a wallet provider from the allow list."""
    await WalletProviderService(db).delete(provider_id)
