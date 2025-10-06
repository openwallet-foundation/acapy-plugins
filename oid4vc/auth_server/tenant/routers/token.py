"""Token endpoint (per-tenant) backed by Authlib AuthorizationServer."""

from fastapi import APIRouter, Depends, Form, Path, Request
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.deps import get_db_session
from tenant.oauth.server import get_authorization_server
from tenant.oauth.integration.request import to_oauth2_request

router = APIRouter(prefix="/tenants/{uid}")


@router.post("/token", tags=["public"])
async def token_endpoint(
    request: Request,
    uid: str = Path(...),
    grant_type: str = Form(
        ...,
        description="Grant type",
        enum=["urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token"],
    ),
    pre_authorized_code: str | None = Form(None, alias="pre-authorized_code"),
    pre_authorized_code_alt: str | None = Form(None, alias="pre_authorized_code"),
    user_pin: str | None = Form(None),
    refresh_token: str | None = Form(None),
    db: AsyncSession = Depends(get_db_session),
):
    """Delegate token issuance to Authlib AuthorizationServer with custom grants."""

    pac_value = pre_authorized_code or pre_authorized_code_alt
    form_data = {
        "grant_type": grant_type,
        "pre-authorized_code": pac_value,
        "pre_authorized_code": pac_value,
        "user_pin": user_pin,
        "refresh_token": refresh_token,
    }
    oauth2_req = await to_oauth2_request(request, db=db, uid=uid, form_data=form_data)
    server = get_authorization_server()
    status_code, body, headers = await server.create_token_response_async(oauth2_req)  # type: ignore[attr-defined]

    return ORJSONResponse(body, status_code=status_code, headers=dict(headers))
