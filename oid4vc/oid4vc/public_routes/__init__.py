"""Public routes for OID4VC."""

from acapy_agent.config.injection_context import InjectionContext
from aiohttp import web

from .credential_offer import dereference_cred_offer
from .metadata import (
    BatchCredentialIssuanceSchema,
    CredentialIssuerMetadataSchema,
    credential_issuer_metadata,
)
from .nonce import create_nonce, request_nonce, NONCE_BYTES, EXPIRES_IN
from .notification import NotificationSchema, receive_notification
from .token import (
    GetTokenSchema,
    token,
    check_token,
    handle_proof_of_posession,
    types_are_subset,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)
from .credential import IssueCredentialRequestSchema, issue_cred
from .verification import (
    OID4VPRequestIDMatchSchema,
    OID4VPPresentationIDMatchSchema,
    PostOID4VPResponseSchema,
    get_request,
    post_response,
    retrieve_or_create_did_jwk,
    verify_dcql_presentation,
    verify_pres_def_presentation,
)
from .status_list import StatusListMatchSchema, get_status_list

from ..pop_result import PopResult
from ..status_handler import StatusHandler
from ..models.issuer_config import IssuerConfiguration
from ..models.supported_cred import SupportedCredential

from oid4vc.jwt import JWTVerifyResult

__all__ = [
    "BatchCredentialIssuanceSchema",
    "CredentialIssuerMetadataSchema",
    "EXPIRES_IN",
    "GetTokenSchema",
    "IssueCredentialRequestSchema",
    "IssuerConfiguration",
    "JWTVerifyResult",
    "NONCE_BYTES",
    "NotificationSchema",
    "OID4VPPresentationIDMatchSchema",
    "OID4VPRequestIDMatchSchema",
    "PRE_AUTHORIZED_CODE_GRANT_TYPE",
    "PopResult",
    "PostOID4VPResponseSchema",
    "StatusListMatchSchema",
    "SupportedCredential",
    "check_token",
    "create_nonce",
    "credential_issuer_metadata",
    "dereference_cred_offer",
    "get_request",
    "get_status_list",
    "handle_proof_of_posession",
    "issue_cred",
    "post_response",
    "receive_notification",
    "register",
    "request_nonce",
    "retrieve_or_create_did_jwk",
    "token",
    "types_are_subset",
    "verify_dcql_presentation",
    "verify_pres_def_presentation",
]


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
            f"/.well-known/openid-credential-issuer{subpath}",
            credential_issuer_metadata,
            allow_head=False,
        ),
        # TODO Add .well-known/did-configuration.json
        # Spec: https://identity.foundation/.well-known/resources/did-configuration/
        web.post(f"{subpath}/token", token),
        web.post(f"{subpath}/nonce", request_nonce),
        web.post(f"{subpath}/notification", receive_notification),
        web.post(f"{subpath}/credential", issue_cred),
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
