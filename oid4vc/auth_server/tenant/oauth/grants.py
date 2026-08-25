"""Custom grant classes for the AuthorizationServer."""

from typing import Any
from urllib.parse import urlparse

from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from fastapi import HTTPException as FastAPIHTTPException
from starlette.requests import Request

from core.consts import OAuth2Flow, OAuth2GrantType
from tenant.config import settings
from tenant.oauth.integration.context import get_context, update_context
from tenant.services.attestation_service import (
    AttestationLookupError,
    validate_client_attestation,
)


class _BaseTenantGrant(grants.BaseGrant):
    """Base grant with no client auth."""

    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    async def authenticate_token_endpoint_client(self):
        """Bypass client authentication."""
        return None

    request: Request

    def _resolve_uid(self) -> str:
        """Resolve tenant UID from request context, falling back to the URL path."""
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
        return uid

    def _resolve_tenant(self) -> tuple[str, Any]:
        """Extract tenant UID and DB session from request context.

        Returns (uid, db). Raises InvalidRequestError on failure.
        """
        uid = self._resolve_uid()
        db = getattr(get_context(self.request), "db", None)
        if db is None:
            raise InvalidRequestError(description="server_error")
        return uid, db

    async def _validate_attestation(self, *, required: bool) -> dict[str, Any] | None:
        """Extract attestation headers and validate against allow list."""
        if not settings.ATTESTATION_ENABLED:
            return None
        headers = getattr(self.request, "headers", {}) or {}
        extra = get_context(self.request)
        # Audience pinning requires the tenant, so resolve it before validating.
        uid = self._resolve_uid()
        try:
            return await validate_client_attestation(
                client_attestation=headers.get("oauth-client-attestation") or None,
                client_attestation_pop=headers.get("oauth-client-attestation-pop")
                or None,
                attestation_required=required,
                expected_audience=f"{settings.ISSUER_BASE_URL}/tenants/{uid}",
                db=getattr(extra, "db", None),
            )
        except AttestationLookupError as ex:
            # Provider trust could not be evaluated; never report as client error.
            raise FastAPIHTTPException(
                status_code=503, detail="attestation_provider_unavailable"
            ) from ex


class PreAuthorizedCodeGrant(_BaseTenantGrant):
    """OID4VCI pre-authorized_code grant."""

    _code: str | None = None
    _tx_code: str | None = None
    _attestation_meta: dict[str, Any] | None = None

    async def validate_token_request(self):
        """Validate pre-authorized_code request."""
        payload = getattr(self.request, "payload", None)
        data = getattr(payload, "data", {}) if payload is not None else {}
        code = data.get("pre-authorized_code") or data.get("pre_authorized_code")
        if not code:
            raise InvalidRequestError(description="missing pre-authorized_code")
        self._code = str(code)
        self._tx_code = data.get("tx_code") or None
        self._attestation_meta = await self._validate_attestation(
            required=settings.ATTESTATION_REQUIRED
        )

    async def create_token_response(self):
        """Create token response for pre-authorized_code."""
        uid, db = self._resolve_tenant()
        # Stash context for save_token
        update_context(
            self.request,
            token_ctx={
                "flow": OAuth2Flow.PRE_AUTH_CODE,
                "uid": uid,
                "code": self._code or "",
                "tx_code": self._tx_code,
                "attestation": self._attestation_meta,
                "realm": uid,
            },
        )
        token_data: dict[str, Any] = {}
        await self.server.save_token(token_data, self.request)
        # Core server appends no-store headers; avoid duplication here
        return 200, token_data, []

    @classmethod
    def check_token_endpoint(cls, request) -> bool:
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
    _attestation_meta: dict[str, Any] | None = None

    async def validate_token_request(self):
        """Validate refresh_token request."""
        payload = getattr(self.request, "payload", None)
        data = getattr(payload, "data", {}) if payload is not None else {}
        refresh_token = data.get("refresh_token") if data else None
        if not refresh_token:
            raise InvalidRequestError(description="missing refresh_token")
        self._refresh_token = str(refresh_token)
        self._attestation_meta = await self._validate_attestation(
            required=settings.ATTESTATION_REQUIRED
        )

    async def create_token_response(self):
        """Create token response for refresh_token."""
        uid, db = self._resolve_tenant()
        # Stash context for save_token
        update_context(
            self.request,
            token_ctx={
                "flow": OAuth2Flow.REFRESH_TOKEN,
                "uid": uid,
                "refresh_token": self._refresh_token or "",
                "attestation": self._attestation_meta,
                "realm": uid,
            },
        )
        token_data: dict[str, Any] = {}
        await self.server.save_token(token_data, self.request)
        # Core server appends no-store headers; avoid duplication here
        return 200, token_data, []

    @classmethod
    def check_token_endpoint(cls, request) -> bool:
        """Return True when request payload grant_type is refresh_token."""
        try:
            payload = getattr(request, "payload", None)
            gt = getattr(payload, "grant_type", None)
            return gt == OAuth2GrantType.REFRESH_TOKEN
        except Exception:
            return False
