"""JSON error responses in the OAuth 2.0 / OID4VCI error format.

``{"error": ..., "error_description": ...}`` bodies, as used by the token
endpoint (RFC 6749 §5.2), resource servers (RFC 6750 §3, RFC 9449 §7.1), the
credential and notification endpoints (OID4VCI 1.0 §7.3.1, §11.3) and the
pre-authorized code redeem endpoint.
"""

import json

from aiohttp import web

_EXCEPTIONS: dict[int, type[web.HTTPException]] = {
    400: web.HTTPBadRequest,
    401: web.HTTPUnauthorized,
    404: web.HTTPNotFound,
}


def _body(error: str, description: str | None) -> dict[str, str]:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return body


def oauth_error_response(
    error: str,
    description: str | None = None,
    status: int = 400,
    *,
    no_store: bool = False,
) -> web.Response:
    """Return an error as a response (for handlers that return responses)."""
    headers = {"Cache-Control": "no-store"} if no_store else None
    return web.json_response(_body(error, description), status=status, headers=headers)


def oauth_error(
    status: int,
    error: str,
    description: str | None = None,
    *,
    www_authenticate: str | None = None,
) -> web.HTTPException:
    """Return an error as an exception to raise.

    ``www_authenticate`` is the auth scheme (e.g. ``Bearer``, ``DPoP``) for a
    ``WWW-Authenticate: <scheme> error="<error>"`` challenge on 401 responses.
    """
    cls = _EXCEPTIONS.get(status, web.HTTPInternalServerError)
    headers = (
        {"WWW-Authenticate": f'{www_authenticate} error="{error}"'}
        if www_authenticate
        else None
    )
    return cls(
        text=json.dumps(_body(error, description)),
        content_type="application/json",
        headers=headers,
    )
