"""Grant service."""

import secrets
import uuid
from datetime import timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.security.utils import utcnow
from tenant.config import settings
from tenant.models import PreAuthCode
from tenant.repositories.grant_repository import GrantRepository
from tenant.repositories.subject_repository import SubjectRepository


def new_code() -> str:
    """Generate a new code."""
    return secrets.token_urlsafe(settings.TOKEN_BYTES)


async def ensure_subject(
    db: AsyncSession, subject_id: str | None, metadata: dict | None
) -> int:
    """Return subject PK by UID, creating if missing."""
    repo = SubjectRepository(db)

    if subject_id:
        sid = await repo.get_id_by_uid(subject_id)
        if sid is not None:
            return sid
        uid = subject_id
    else:
        uid = str(uuid.uuid4())

    try:
        subj = await repo.create(uid=uid, metadata=metadata or {})
        return subj.id
    except IntegrityError:
        # Race: subject with this uid created concurrently
        sid2 = await repo.get_id_by_uid(uid)
        if sid2 is None:
            raise
        return sid2


async def create_pre_authorized_code(
    db: AsyncSession,
    subject_id: str | None,
    subject_metadata: dict | None,
    user_pin_required: bool,
    user_pin: str | None,
    authorization_details: list | None,
    ttl_seconds: int | None,
) -> PreAuthCode:
    """Create a pre-auth code with TTL."""
    sid = await ensure_subject(db, subject_id, subject_metadata)
    if authorization_details:
        authorization_details_dict = [ad.model_dump() for ad in authorization_details]
    else:
        authorization_details_dict = None
    now = utcnow()
    ttl = ttl_seconds if ttl_seconds and ttl_seconds > 0 else settings.PRE_AUTH_CODE_TTL
    repo = GrantRepository(db)
    pac = await repo.create_pre_auth_code(
        subject_id=sid,
        code=new_code(),
        user_pin=user_pin,
        user_pin_required=bool(user_pin_required),
        authorization_details=authorization_details_dict,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    await db.commit()
    await db.refresh(pac)
    return pac
