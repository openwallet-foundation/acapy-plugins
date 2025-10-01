"""Sign JWTs via the admin API."""

from typing import Any

import httpx

from core.observability.observability import current_request_id
from core.utils.retry import with_retries
from tenant.config import settings


@with_retries(
    max_attempts=3,
    base_delay=0.2,
    max_delay=2.0,
    retry_on=(httpx.RequestError, httpx.HTTPStatusError),
    should_retry=lambda e: isinstance(e, httpx.RequestError)
    or (
        isinstance(e, httpx.HTTPStatusError)
        and getattr(e, "response", None) is not None
        and e.response.status_code >= 500
    ),
)
async def remote_sign_jwt(
    *, uid: str, claims: dict, kid: str | None = None
) -> dict[str, Any]:
    """Sign a JWT via the admin API (with retries for transient errors)."""
    url = f"{settings.ADMIN_INTERNAL_BASE_URL}/tenants/{uid}/jwts"
    payload: dict[str, Any] = {"claims": claims}
    if kid:
        payload["kid"] = kid
    headers = {"Authorization": f"Bearer {settings.ADMIN_INTERNAL_AUTH_TOKEN}"}
    rid = current_request_id()
    if rid:
        headers["X-Request-ID"] = rid
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(url, json=payload, headers=headers)
        # 4xx and 5xx will be handled by decorator's should_retry predicate
        res.raise_for_status()
        return res.json()
