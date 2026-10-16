"""Build OAuth2Request from FastAPI Request for Authlib core server."""

from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload, OAuth2Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from tenant.oauth.integration.context import set_context


async def to_oauth2_request(
    request: Request,
    *,
    db: AsyncSession | None = None,
    uid: str | None = None,
    form_data: dict[str, str | None] | None = None,
) -> OAuth2Request:
    """Convert FastAPI Request to OAuth2Request and attach context."""

    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        # RFC 9110 §5.3: combine repeated fields so validators can reject duplicates.
        headers[name] = f"{headers[name]}, {value}" if name in headers else value

    oauth2_req = OAuth2Request(
        method=request.method,
        uri=str(request.url),
        headers=headers,
    )
    form_data = form_data or {}
    data = {k: v for k, v in form_data.items() if v is not None}
    oauth2_req.payload = BasicOAuth2Payload(data)

    set_context(oauth2_req, db=db, uid=uid)

    return oauth2_req
