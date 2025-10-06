"""Client service."""

import uuid

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.repositories.client_repository import ClientRepository
from admin.schemas.client import ClientIn
from core.consts import CLIENT_AUTH_METHODS, ClientAuthMethod
from core.crypto.crypto import hash_secret_pbkdf2
from core.models import Client


class ClientService:
    """Client orchestration."""

    def __init__(self, session: AsyncSession):
        """Constructor."""
        self.session = session
        self.repo = ClientRepository(session)

    async def create(self, data: ClientIn) -> Client:
        """Create a client record in db."""

        # Validate method
        method = (data.client_auth_method or "").lower()
        if method not in set(CLIENT_AUTH_METHODS):
            raise HTTPException(status_code=400, detail="invalid_method")

        # Defaults per method
        signing_alg = data.client_auth_signing_alg
        if not signing_alg:
            if method == ClientAuthMethod.PRIVATE_KEY_JWT:
                signing_alg = "ES256"
            elif method == ClientAuthMethod.SHARED_KEY_JWT:
                signing_alg = "HS256"

        # Validate fields by method
        secret_hash: str | None = None
        if method == ClientAuthMethod.PRIVATE_KEY_JWT:
            if not (data.jwks or data.jwks_uri):
                raise HTTPException(status_code=400, detail="jwks_or_uri_required")
        elif method in (
            ClientAuthMethod.SHARED_KEY_JWT,
            ClientAuthMethod.CLIENT_SECRET_BASIC,
        ):
            if not data.client_secret:
                raise HTTPException(status_code=400, detail="client_secret_required")
            if method == ClientAuthMethod.CLIENT_SECRET_BASIC:
                secret_hash = hash_secret_pbkdf2(data.client_secret)
            else:
                secret_hash = data.client_secret

        client_id = data.client_id or uuid.uuid4().hex

        if await self.repo.get_by_client_id(client_id):
            raise HTTPException(status_code=409, detail="client_exists")

        client = Client(
            client_id=client_id,
            client_auth_method=method,
            client_auth_signing_alg=signing_alg,
            client_secret=secret_hash,
            jwks=data.jwks,
            jwks_uri=data.jwks_uri,
        )

        self.session.add(client)
        await self.session.commit()

        return client

    async def list(self) -> list[Client]:
        """List all clients."""
        rows = await self.repo.list()
        return list(rows)

    async def get(self, client_id: str) -> Client | None:
        """Get client by client_id."""
        return await self.repo.get_by_client_id(client_id)

    async def update(self, client_id: str, data: ClientIn) -> int:
        """Update client basic fields; returns rows changed."""
        row = await self.repo.get_by_client_id(client_id)
        if not row:
            raise HTTPException(status_code=404, detail="client_not_found")
        values = {
            k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None
        }
        changed = await self.repo.update_values(row.id, values)
        await self.session.commit()
        return changed

    async def delete(self, client_id: str) -> int:
        """Delete a client; returns rows deleted."""
        row = await self.repo.get_by_client_id(client_id)
        if not row:
            raise HTTPException(status_code=404, detail="client_not_found")
        deleted = await self.repo.delete(row.id)
        await self.session.commit()
        return deleted
