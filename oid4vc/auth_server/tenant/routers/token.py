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
    pre_authorized_code: str | None = Form(None),
    tx_code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    db: AsyncSession = Depends(get_db_session),
):
    """Delegate token issuance to Authlib AuthorizationServer with custom grants."""

    # Real OID4VCI wallets send "pre-authorized_code" (hyphen); Swagger sends
    # "pre_authorized_code" (underscore). Accept both.
    pac_value = pre_authorized_code
    if not pac_value:
        raw_form = await request.form()
        pac_value = raw_form.get("pre-authorized_code") or None  # type: ignore[assignment]

    form_data = {
        "grant_type": grant_type,
        "pre-authorized_code": pac_value,
        "pre_authorized_code": pac_value,
        "tx_code": tx_code,
        "refresh_token": refresh_token,
    }
    oauth2_req = await to_oauth2_request(request, db=db, uid=uid, form_data=form_data)
    server = get_authorization_server()
    status_code, body, headers = await server.create_token_response_async(oauth2_req)  # type: ignore[attr-defined]

    resp_headers = dict(headers)
    resp_headers["Cache-Control"] = "no-store"
    resp_headers["Pragma"] = "no-cache"
    return ORJSONResponse(body, status_code=status_code, headers=resp_headers)
