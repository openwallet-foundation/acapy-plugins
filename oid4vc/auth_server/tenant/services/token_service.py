"""Issue/rotate tokens via remote signer, using tenant DB only."""

import secrets
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.security.utils import (
    compute_access_exp,
    compute_refresh_exp,
    hash_token,
    new_refresh_token,
    utcnow,
)
from tenant.config import settings
from tenant.repositories.access_token_repository import AccessTokenRepository
from tenant.repositories.grant_repository import GrantRepository
from tenant.repositories.refresh_token_repository import RefreshTokenRepository
from tenant.services.signing_service import remote_sign_jwt


def _coerce_authorization_details(value: Any) -> list[dict[str, Any]]:
    """Return authorization_details as a list of dicts, filtering invalid entries."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


class TokenService:
    """Issue/rotate tokens via remote signer, using tenant DB only."""

    @staticmethod
    async def issue_by_pre_auth_code(
        db: AsyncSession,
        uid: str,
        code: str,
        realm: str,
        user_pin: str | None = None,
    ):
        """Issue access+refresh from a pre-auth code."""
        grant_repo = GrantRepository(db)
        access_repo = AccessTokenRepository(db)
        refresh_repo = RefreshTokenRepository(db)

        issuer = f"{settings.ISSUER_BASE_URL}/tenants/{uid}"
        now = utcnow()

        pac = await grant_repo.get_by_code(code)
        if pac is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant"
            )
        if pac.user_pin_required and (not user_pin or user_pin != (pac.user_pin or "")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant"
            )
        # Atomically consume the PAC to prevent race/double-spend
        consumed = await grant_repo.consume_valid(pac.id, now)
        if not consumed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant"
            )

        if not pac.subject or not pac.subject.uid:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="subject_uid_missing",
            )
        access_exp = compute_access_exp(now)
        claims = {
            "iss": issuer,
            "sub": pac.subject.uid,
            "iat": int(now.timestamp()),
            "exp": int(access_exp.timestamp()),
        }
        response_meta: dict[str, Any] = {}
        auth_details = _coerce_authorization_details(pac.authorization_details)
        if auth_details:
            response_meta["authorization_details"] = auth_details
        if settings.INCLUDE_NONCE:
            c_nonce = secrets.token_urlsafe(settings.NONCE_BYTES)
            c_nonce_expires_in = settings.ACCESS_TOKEN_TTL
            response_meta["c_nonce"] = c_nonce
            response_meta["c_nonce_expires_in"] = c_nonce_expires_in

        sign_res = await remote_sign_jwt(
            uid=uid,
            claims=claims,
        )

        token_meta: dict[str, Any] = {"iss": issuer, "realm": realm}
        token_meta.update(response_meta)
        access_token = await access_repo.create(
            subject_id=pac.subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
        )

        refresh_token = new_refresh_token()
        _ = await refresh_repo.create(
            subject_id=pac.subject_id,
            access_token_id=access_token.id,
            token_hash=hash_token(refresh_token),
            issued_at=now,
            expires_at=compute_refresh_exp(now),
            token_metadata={"realm": realm},
        )
        await db.commit()
        return access_token, refresh_token, response_meta

    @staticmethod
    async def rotate_by_refresh_token(
        db: AsyncSession,
        uid: str,
        refresh_token_value: str,
        realm: str,
    ):
        """Rotate tokens using a refresh token."""
        access_repo = AccessTokenRepository(db)
        refresh_repo = RefreshTokenRepository(db)

        issuer = f"{settings.ISSUER_BASE_URL}/tenants/{uid}"
        now = utcnow()
        access_exp = compute_access_exp(now)

        token_hash = hash_token(refresh_token_value)
        res = await refresh_repo.consume_valid(token_hash=token_hash, now=now)
        if not res:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token"
            )
        subject_id, access_token_id = res

        prev_access = await access_repo.get_by_id(access_token_id)
        if not prev_access or not prev_access.subject or not prev_access.subject.uid:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="subject_uid_missing",
            )
        prev_meta = prev_access.token_metadata or {}
        prev_authz = (
            _coerce_authorization_details(prev_meta.get("authorization_details"))
            if isinstance(prev_meta, dict)
            else []
        )
        claims = {
            "iss": issuer,
            "sub": prev_access.subject.uid,
            "iat": int(now.timestamp()),
            "exp": int(access_exp.timestamp()),
        }
        response_meta: dict[str, Any] = {}
        if prev_authz:
            response_meta["authorization_details"] = prev_authz
        if settings.INCLUDE_NONCE:
            c_nonce = secrets.token_urlsafe(settings.NONCE_BYTES)
            c_nonce_expires_in = settings.ACCESS_TOKEN_TTL
            response_meta["c_nonce"] = c_nonce
            response_meta["c_nonce_expires_in"] = c_nonce_expires_in

        sign_res = await remote_sign_jwt(
            uid=uid,
            claims=claims,
        )

        token_meta = {"iss": issuer, "realm": realm}
        token_meta.update(response_meta)
        new_access_token = await access_repo.create(
            subject_id=subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
        )

        refresh_token = new_refresh_token()
        _ = await refresh_repo.create(
            subject_id=subject_id,
            access_token_id=new_access_token.id,
            token_hash=hash_token(refresh_token),
            issued_at=now,
            expires_at=compute_refresh_exp(now),
            token_metadata={"realm": realm},
        )
        await db.commit()
        return new_access_token, refresh_token, response_meta
