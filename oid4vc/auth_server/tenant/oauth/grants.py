"""Custom grant classes for the AuthorizationServer."""

from typing import Any
from urllib.parse import urlparse

from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from starlette.requests import Request

from core.consts import OAuth2Flow, OAuth2GrantType
from tenant.oauth.integration.context import get_context, update_context


class _BaseTenantGrant(grants.BaseGrant):
    """Base grant with no client auth."""

    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    async def authenticate_token_endpoint_client(self):  # type: ignore[override]
        """Bypass client authentication."""
        return None

    request: Request


class PreAuthorizedCodeGrant(_BaseTenantGrant):
    """OID4VCI pre-authorized_code grant."""

    _code: str | None = None
    _user_pin: str | None = None

    async def validate_token_request(self):  # type: ignore[override]
        """Validate pre-authorized_code request."""
        payload = getattr(self.request, "payload", None)
        data = getattr(payload, "data", {}) if payload is not None else {}
        code = data.get("pre-authorized_code") or data.get("pre_authorized_code")
        if not code:
            raise InvalidRequestError(description="missing pre-authorized_code")
        self._code = str(code)
        self._user_pin = data.get("user_pin") or None

    async def create_token_response(self):  # type: ignore[override]
        """Create token response for pre-authorized_code."""
        extra = get_context(self.request)
        uid = getattr(extra, "uid", None)
        if not uid:
            url = getattr(self.request, "uri", None) or getattr(self.request, "url", "")
            path = urlparse(url).path if url else ""
            parts = [p for p in path.split("/") if p]
            try:
                tidx = parts.index("tenants")
                uid = parts[tidx + 1]
            except Exception:
                uid = None
        if not uid:
            raise InvalidRequestError(description="missing_tenant_uid")
        db = getattr(extra, "db", None)
        if db is None:
            raise InvalidRequestError(description="server_error")
        # Stash context for save_token
        update_context(
            self.request,
            token_ctx={
                "flow": OAuth2Flow.PRE_AUTH_CODE,
                "uid": uid,
                "code": self._code or "",
                "user_pin": self._user_pin,
                "realm": uid,
            },
        )
        token_data: dict[str, Any] = {}
        await self.server.save_token(token_data, self.request)
        # Core server appends no-store headers; avoid duplication here
        return 200, token_data, []

    @classmethod
    def check_token_endpoint(cls, request) -> bool:  # type: ignore[override]
        """Return True when request payload grant_type matches."""
        try:
            payload = getattr(request, "payload", None)
            gt = getattr(payload, "grant_type", None)
            return gt == OAuth2GrantType.PRE_AUTH_CODE
        except Exception:
            return False


class RotatingRefreshTokenGrant(_BaseTenantGrant):
    """Refresh token grant with rotation."""

    _refresh_token: str | None = None

    async def validate_token_request(self):  # type: ignore[override]
        """Validate refresh_token request."""
        payload = getattr(self.request, "payload", None)
        data = getattr(payload, "data", {}) if payload is not None else {}
        refresh_token = data.get("refresh_token") if data else None
        if not refresh_token:
            raise InvalidRequestError(description="missing refresh_token")
        self._refresh_token = str(refresh_token)

    async def create_token_response(self):  # type: ignore[override]
        """Create token response for refresh_token."""
        extra = get_context(self.request)
        uid = getattr(extra, "uid", None)
        if not uid:
            url = getattr(self.request, "uri", None) or getattr(self.request, "url", "")
            path = urlparse(url).path if url else ""
            parts = [p for p in path.split("/") if p]
            try:
                tidx = parts.index("tenants")
                uid = parts[tidx + 1]
            except Exception:
                uid = None
        if not uid:
            raise InvalidRequestError(description="missing_tenant_uid")
        db = getattr(extra, "db", None)
        if db is None:
            raise InvalidRequestError(description="server_error")
        # Stash context for save_token
        update_context(
            self.request,
            token_ctx={
                "flow": OAuth2Flow.REFRESH_TOKEN,
                "uid": uid,
                "refresh_token": self._refresh_token or "",
                "realm": uid,
            },
        )
        token_data: dict[str, Any] = {}
        await self.server.save_token(token_data, self.request)
        # Core server appends no-store headers; avoid duplication here
        return 200, token_data, []

    @classmethod
    def check_token_endpoint(cls, request) -> bool:  # type: ignore[override]
        """Return True when request payload grant_type is refresh_token."""
        try:
            payload = getattr(request, "payload", None)
            gt = getattr(payload, "grant_type", None)
            return gt == OAuth2GrantType.REFRESH_TOKEN
        except Exception:
            return False
