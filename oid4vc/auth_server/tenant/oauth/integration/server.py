"""Authlib core AuthorizationServer adapter for FastAPI/Starlette."""

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import (
    InvalidRequestError,
    OAuth2Error,
    UnsupportedGrantTypeError,
)
from authlib.oauth2.rfc6749.requests import OAuth2Request

NO_STORE = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]


class CoreAuthorizationServer(AuthorizationServer):
    """AuthorizationServer that accepts prebuilt OAuth2Request objects."""

    def create_oauth2_request(self, request) -> OAuth2Request:  # type: ignore[override]
        """Expect callers (routes) to build OAuth2Request."""
        if isinstance(request, OAuth2Request):
            return request
        raise InvalidRequestError(description="server_error")

    def handle_response(self, status_code: int, payload, headers):  # type: ignore[override]
        """Return (status, body, headers) and add no-store."""
        return status_code, payload, headers + NO_STORE

    def handle_error_response(self, request, error):
        """Return (status, body, headers) and add no-store."""
        status, payload, headers = super().handle_error_response(request, error)  # type: ignore[misc]
        return status, payload, headers + NO_STORE

    async def create_token_response_async(
        self, request
    ) -> tuple[int, dict, list[tuple[str, str]]]:
        """Async wrapper compatible with async grants and save_token."""
        req = self.create_oauth2_request(request)
        try:
            grant = self.get_token_grant(req)
        except UnsupportedGrantTypeError as error:
            return self.handle_error_response(req, error)

        try:
            await grant.validate_token_request()  # type: ignore[func-returns-value]
            args = await grant.create_token_response()  # type: ignore[func-returns-value]
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(req, error)
