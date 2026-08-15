"""Issue/rotate tokens via remote signer, using tenant DB only."""

import hmac
import secrets
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils.logging import get_logger

from core.security.utils import (
    hash_token,
    utcnow,
)
from tenant.config import settings
from tenant.models import Subject
from tenant.repositories.access_token_repository import AccessTokenRepository
from tenant.repositories.grant_repository import GrantRepository
from tenant.repositories.refresh_token_repository import RefreshTokenRepository
from tenant.security.token import (
    compute_access_exp,
    compute_refresh_exp,
    new_refresh_token,
)
from tenant.services.signing_service import remote_sign_jwt

logger = get_logger(__name__)


def _coerce_authorization_details(value: Any) -> list[dict[str, Any]]:
    """Return authorization_details as a list of dicts, filtering invalid entries."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _coerce_amr(value: Any) -> list[str]:
    """Return amr as a list of non-empty strings."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _merge_amr(existing: Any, value: str) -> list[str]:
    """Return unique AMR values preserving order."""
    amr_values = _coerce_amr(existing)
    if value not in amr_values:
        amr_values.append(value)
    return amr_values


class TokenService:
    """Issue/rotate tokens via remote signer, using tenant DB only."""

    @staticmethod
    async def issue_by_pre_auth_code(
        db: AsyncSession,
        uid: str,
        code: str,
        realm: str,
        tx_code: str | None = None,
        attestation: dict[str, Any] | None = None,
    ):
        """Issue access+refresh from a pre-auth code."""
        grant_repo = GrantRepository(db)
        access_repo = AccessTokenRepository(db)
        refresh_repo = RefreshTokenRepository(db)

        issuer = f"{settings.ISSUER_BASE_URL}/tenants/{uid}"
        now = utcnow()

        pac = await grant_repo.get_by_code(code)
        if pac is None or pac.used or pac.expires_at <= now:
            reason = (
                "not_found" if pac is None else "already_used" if pac.used else "expired"
            )
            logger.warning("pre_auth_code rejected: %s", reason)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant"
            )
        # tx_code brute-force check
        if pac.tx_code and not hmac.compare_digest(tx_code or "", pac.tx_code):
            attempts = await grant_repo.increment_tx_code_attempts(
                pac.id, settings.MAX_TX_CODE_ATTEMPTS
            )
            await db.commit()
            remaining = max(0, settings.MAX_TX_CODE_ATTEMPTS - attempts)
            detail = "invalid_grant" if remaining == 0 else "invalid_tx_code"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
        # Consume the PAC atomically (prevents double-spend)
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
        if isinstance(attestation, dict):
            response_meta["attestation"] = attestation
            response_meta["amr"] = _merge_amr(response_meta.get("amr"), "att-pop")

        sign_res = await remote_sign_jwt(uid=uid, claims=claims)

        token_meta: dict[str, Any] = {"iss": issuer, "realm": realm}
        token_meta.update(response_meta)
        cnf_jkt = attestation.get("cnf_jkt") if isinstance(attestation, dict) else None
        access_token = await access_repo.create(
            subject_id=pac.subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
            cnf_jkt=cnf_jkt,
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
        attestation: dict[str, Any] | None = None,
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
            # Check if this is a reuse of an already-consumed token (breach signal)
            reuse_subject = await refresh_repo.is_token_reuse(token_hash)
            if reuse_subject is not None:
                logger.warning(
                    "refresh token reuse detected, revoking family subject_id=%s",
                    reuse_subject,
                )
                # SELECT FOR UPDATE to serialize concurrent issuance
                # before revoking the subject's token family.
                await db.execute(
                    select(Subject.id)
                    .where(Subject.id == reuse_subject)
                    .with_for_update()
                )
                # Revoke the token family (OAuth Security BCP §4.14.2)
                await access_repo.revoke_all_for_subject(reuse_subject)
                await refresh_repo.revoke_all_for_subject(reuse_subject)
                await db.commit()
            else:
                logger.warning("refresh token not found or expired")
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
        # draft-07 10.3: the refresh token is bound to the attested client instance
        # key, so rotation MUST present the same key.
        bound_cnf_jkt = getattr(prev_access, "cnf_jkt", None) or None
        if bound_cnf_jkt:
            presented_cnf_jkt = (
                attestation.get("cnf_jkt") if isinstance(attestation, dict) else None
            )
            if presented_cnf_jkt != bound_cnf_jkt:
                logger.warning(
                    "refresh attestation key mismatch subject_id=%s", subject_id
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid_token",
                )

        # Revoke the previous access token immediately on rotation
        prev_access.revoked = True
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

        effective_attestation = None
        if isinstance(attestation, dict):
            effective_attestation = attestation
        elif isinstance(prev_meta, dict) and isinstance(
            prev_meta.get("attestation"), dict
        ):
            effective_attestation = prev_meta.get("attestation")
        if isinstance(effective_attestation, dict):
            response_meta["attestation"] = effective_attestation

        amr_values = (
            _coerce_amr(prev_meta.get("amr")) if isinstance(prev_meta, dict) else []
        )
        if isinstance(effective_attestation, dict):
            amr_values = _merge_amr(amr_values, "att-pop")
        if amr_values:
            response_meta["amr"] = amr_values

        sign_res = await remote_sign_jwt(uid=uid, claims=claims)

        token_meta: dict[str, Any] = {"iss": issuer, "realm": realm}
        token_meta.update(response_meta)
        cnf_jkt = (
            effective_attestation.get("cnf_jkt")
            if isinstance(effective_attestation, dict)
            else None
        )
        new_access_token = await access_repo.create(
            subject_id=subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
            cnf_jkt=cnf_jkt,
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
