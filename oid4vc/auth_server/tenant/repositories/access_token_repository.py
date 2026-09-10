"""AccessToken repository."""

from datetime import datetime
from typing import Union

from sqlalchemy import select

from tenant.models import AccessToken
from tenant.repositories.base import BaseTokenRepository


class AccessTokenRepository(BaseTokenRepository):
    """Repository for access tokens."""

    _model = AccessToken

    async def create(
        self,
        subject_id: int,
        token: str,
        issued_at: Union[int, float, datetime],
        expires_at: Union[int, float, datetime],
        token_metadata: dict | None = None,
        cnf_jkt: str | None = None,
    ) -> AccessToken:
        """Create and add a new access token."""
        issued_dt = self._to_dt(issued_at)
        expires_dt = self._to_dt(expires_at)
        access_token = AccessToken(
            subject_id=subject_id,
            token=token,
            issued_at=issued_dt,
            expires_at=expires_dt,
            token_metadata=token_metadata or {},
            cnf_jkt=cnf_jkt,
        )
        self.db.add(access_token)
        await self.db.flush()
        return access_token

    async def get_by_id(self, access_token_id: int) -> AccessToken | None:
        """Get access token by ID with subject eagerly loaded."""
        stmt = select(AccessToken).where(AccessToken.id == access_token_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_token(self, token: str) -> AccessToken | None:
        """Get access token by ID with subject eagerly loaded."""
        stmt = select(AccessToken).where(AccessToken.token == token)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()
