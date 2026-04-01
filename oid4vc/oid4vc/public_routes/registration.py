"""Route registration for OID4VC public routes."""

from acapy_agent.config.injection_context import InjectionContext
from aiohttp import web

from ..status_handler import StatusHandler
from .credential import dereference_cred_offer, issue_cred
from .metadata import credential_issuer_metadata, openid_configuration
from .nonce import get_nonce
from .notification import receive_notification
from .status_list import get_status_list
from .token import token
from .verification import get_request, post_response


async def credential_issuer_metadata_deprecated(request: web.Request) -> web.Response:
    """Deprecated underscore endpoint wrapper - adds deprecation headers.

    The underscore variant (/.well-known/openid_credential_issuer) was used in
    early OID4VCI drafts. The canonical OID4VCI 1.0 endpoint uses a dash
    (/.well-known/openid-credential-issuer). This wrapper adds standard
    HTTP deprecation headers to signal clients to migrate to the standard
    endpoint.
    """
    response = await credential_issuer_metadata(request)
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "Deprecated: use /.well-known/openid-credential-issuer"'
    )
    response.headers["Sunset"] = "Sat, 01 Jan 2028 00:00:00 GMT"
    return response


async def register(app: web.Application, multitenant: bool, context: InjectionContext):
    """Register routes with support for multitenant mode.

    Adds the subpath with Wallet ID as a path parameter if multitenant is True.
    """
    subpath = "/tenant/{wallet_id}" if multitenant else ""
    routes = [
        web.get(
            f"{subpath}/oid4vci/dereference-credential-offer",
            dereference_cred_offer,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-credential-issuer",
            credential_issuer_metadata,
            allow_head=False,
        ),
        # OID4VCI 1.0 spec uses underscore; dash variant is kept for compatibility
        web.get(
            f"{subpath}/.well-known/openid_credential_issuer",
            credential_issuer_metadata_deprecated,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-configuration",
            openid_configuration,
            allow_head=False,
        ),
        # RFC 8414 Authorization Server Metadata endpoint - required by OID4VCI
        # conformance suite (VCIFetchOAuthorizationServerMetadata). ACA-Py serves
        # the same content as /.well-known/openid-configuration.
        web.get(
            f"{subpath}/.well-known/oauth-authorization-server",
            openid_configuration,
            allow_head=False,
        ),
        # TODO Add .well-known/did-configuration.json
        # Spec: https://identity.foundation/.well-known/resources/did-configuration/
        web.post(f"{subpath}/token", token),
        web.post(f"{subpath}/notification", receive_notification),
        web.post(f"{subpath}/credential", issue_cred),
        # OID4VCI nonce endpoint — provides server-generated nonces for proof-of-
        # possession in HAIP and other profiles that require nonce_endpoint in metadata.
        web.post(f"{subpath}/nonce", get_nonce),
        web.get(f"{subpath}/nonce", get_nonce),
        web.get(f"{subpath}/oid4vp/request/{{request_id}}", get_request),
        web.post(f"{subpath}/oid4vp/response/{{presentation_id}}", post_response),
    ]
    # Conditionally add status route
    if context.inject_or(StatusHandler):
        routes.append(
            web.get(
                f"{subpath}/status/{{list_number}}", get_status_list, allow_head=False
            )
        )
    # Add the routes to the application
    app.add_routes(routes)
