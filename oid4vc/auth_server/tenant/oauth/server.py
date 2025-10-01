"""Authlib AuthorizationServer wiring with custom grants."""

from typing import Any

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    InvalidRequestError,
)
from fastapi import HTTPException as FastAPIHTTPException

from core.consts import OAuth2Flow
from tenant.oauth.grants import PreAuthorizedCodeGrant, RotatingRefreshTokenGrant
from tenant.oauth.integration.context import get_context
from tenant.oauth.integration.server import CoreAuthorizationServer
from tenant.services.token_service import TokenService

_server: AuthorizationServer | None = None


def get_authorization_server() -> AuthorizationServer:
    """Return singleton AuthorizationServer with custom grants."""

    global _server
    if _server is not None:
        return _server

    async def _save_token(token: dict[str, Any], request: Any):  # pragma: no cover
        """Persist tokens based on flow context and finalize payload."""
        extra = get_context(request)
        ctx = getattr(extra, "token_ctx", None) or {}
        uid = getattr(extra, "uid", None)
        db = getattr(extra, "db", None)
        if not uid or db is None or not isinstance(ctx, dict):
            raise InvalidRequestError(description="server_error")

        flow = ctx.get("flow")
        realm = ctx.get("realm") or uid

        try:
            if flow == OAuth2Flow.PRE_AUTH_CODE:
                code = ctx.get("code") or ""
                user_pin = ctx.get("user_pin")
                (
                    access_token,
                    refresh_token,
                    response_meta,
                ) = await TokenService.issue_by_pre_auth_code(
                    db=db,
                    uid=uid,
                    code=code,
                    realm=realm,
                    user_pin=user_pin,
                )
                token.update(
                    {
                        "access_token": access_token.token,
                        "refresh_token": refresh_token,
                        "token_type": "Bearer",
                        "expires_in": int(
                            (
                                access_token.expires_at - access_token.issued_at
                            ).total_seconds()
                        ),
                    }
                )
                if response_meta.get("authorization_details"):
                    token["authorization_details"] = response_meta[
                        "authorization_details"
                    ]
                if response_meta.get("c_nonce"):
                    token["c_nonce"] = response_meta["c_nonce"]
                if response_meta.get("c_nonce_expires_in"):
                    token["c_nonce_expires_in"] = int(response_meta["c_nonce_expires_in"])
                return

            if flow == OAuth2Flow.REFRESH_TOKEN:
                refresh_token = ctx.get("refresh_token") or ""
                (
                    new_access,
                    new_refresh_token,
                    response_meta,
                ) = await TokenService.rotate_by_refresh_token(
                    db=db,
                    uid=uid,
                    refresh_token_value=refresh_token,
                    realm=realm,
                )
                token.update(
                    {
                        "access_token": new_access.token,
                        "refresh_token": new_refresh_token,
                        "token_type": "Bearer",
                        "expires_in": int(
                            (new_access.expires_at - new_access.issued_at).total_seconds()
                        ),
                    }
                )
                if response_meta.get("authorization_details"):
                    token["authorization_details"] = response_meta[
                        "authorization_details"
                    ]
                if response_meta.get("c_nonce"):
                    token["c_nonce"] = response_meta["c_nonce"]
                if response_meta.get("c_nonce_expires_in"):
                    token["c_nonce_expires_in"] = int(response_meta["c_nonce_expires_in"])
                return
        except FastAPIHTTPException as e:  # map service errors to OAuth errors
            if e.status_code == 400:
                detail = getattr(e, "detail", None)
                if detail == "invalid_grant":
                    raise InvalidGrantError(description="invalid_grant")
                raise InvalidRequestError(description="invalid_request")
            if e.status_code == 401:
                raise InvalidGrantError(description="invalid_grant")
            raise InvalidRequestError(description="server_error")
        except Exception:
            raise InvalidRequestError(description="server_error")

        raise InvalidRequestError(description="unknown_token_flow")

    _server = CoreAuthorizationServer()
    _server.save_token = _save_token  # type: ignore[attr-defined]
    _server.register_grant(PreAuthorizedCodeGrant)
    _server.register_grant(RotatingRefreshTokenGrant)

    return _server
