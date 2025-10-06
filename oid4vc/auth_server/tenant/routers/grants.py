"""Pre-authorized code issuance (per-tenant)."""

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import Client as AuthClient
from tenant.deps import get_db_session
from tenant.schemas.grant import PreAuthGrantIn, PreAuthGrantOut
from tenant.security.client_auth import client_auth
from tenant.services.grant_service import create_pre_authorized_code

router = APIRouter(prefix="/tenants/{uid}")


@router.post(
    "/grants/pre-authorized-code",
    tags=["protected"],
    response_model=PreAuthGrantOut,
    response_class=ORJSONResponse,
)
async def issue_pre_authorized_code(
    body: PreAuthGrantIn,
    uid: str = Path(...),
    client: AuthClient = Depends(client_auth),
    db: AsyncSession = Depends(get_db_session),
):
    """Issue a pre-authorized code for the current tenant."""
    pac = await create_pre_authorized_code(
        db=db,
        subject_id=body.subject_id,
        subject_metadata=body.subject_metadata,
        user_pin_required=body.user_pin_required,
        user_pin=body.user_pin,
        authorization_details=body.authorization_details,
        ttl_seconds=body.ttl_seconds,
    )
    if not pac:
        raise HTTPException(status_code=500, detail="failed_to_create_pre_auth_code")

    if not pac.subject or not pac.subject.uid:
        raise HTTPException(status_code=500, detail="subject_uid_missing")

    return PreAuthGrantOut(
        pre_authorized_code=pac.code,
        user_pin_required=pac.user_pin_required,
        user_pin=pac.user_pin,
        subject_id=pac.subject.uid,
    )
