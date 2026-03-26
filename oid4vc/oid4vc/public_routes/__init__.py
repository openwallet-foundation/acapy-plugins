"""Public routes package for OID4VC.

This package provides HTTP endpoints for OpenID4VC protocols:
- Token endpoint for pre-authorized code flow
- Credential issuance endpoints
- Metadata endpoints
- OID4VP verification endpoints
- Status list endpoints
"""

# Constants
from .constants import EXPIRES_IN, NONCE_BYTES, PRE_AUTHORIZED_CODE_GRANT_TYPE

# Pop Result
from ..pop_result import PopResult

# Credential issuance
from .credential import (
    IssueCredentialRequestSchema,
    dereference_cred_offer,
    issue_cred,
    types_are_subset,
)

# Metadata
from .metadata import (
    BatchCredentialIssuanceSchema,
    CredentialIssuerMetadataSchema,
    credential_issuer_metadata,
    openid_configuration,
)

# Nonce management
from .nonce import create_nonce, get_nonce

# Notification
from .notification import NotificationSchema, receive_notification

# Route registration
from .registration import register

# Status list
from .status_list import StatusListMatchSchema, get_status_list

# Token endpoint
from .token import (
    GetTokenSchema,
    JWTVerifyResult,
    check_token,
    handle_proof_of_posession,
    token,
)

# Verification
from .verification import (
    OID4VPPresentationIDMatchSchema,
    OID4VPRequestIDMatchSchema,
    PostOID4VPResponseSchema,
    get_request,
    post_response,
    verify_dcql_presentation,
    verify_pres_def_presentation,
)
from ..did_utils import (
    _create_default_did,
    _retrieve_default_did,
    retrieve_or_create_did_jwk,
)

__all__ = [
    # Constants
    "EXPIRES_IN",
    "NONCE_BYTES",
    "PRE_AUTHORIZED_CODE_GRANT_TYPE",
    # Pop Result
    "PopResult",
    # Credential issuance
    "IssueCredentialRequestSchema",
    "dereference_cred_offer",
    "issue_cred",
    "types_are_subset",
    # Metadata
    "BatchCredentialIssuanceSchema",
    "CredentialIssuerMetadataSchema",
    "credential_issuer_metadata",
    "openid_configuration",
    # Nonce
    "create_nonce",
    "get_nonce",
    # Notification
    "NotificationSchema",
    "receive_notification",
    # Registration
    "register",
    # Status list
    "StatusListMatchSchema",
    "get_status_list",
    # Token
    "GetTokenSchema",
    "JWTVerifyResult",
    "check_token",
    "handle_proof_of_posession",
    "token",
    # Verification
    "OID4VPPresentationIDMatchSchema",
    "OID4VPRequestIDMatchSchema",
    "PostOID4VPResponseSchema",
    "_create_default_did",
    "_retrieve_default_did",
    "get_request",
    "post_response",
    "retrieve_or_create_did_jwk",
    "verify_dcql_presentation",
    "verify_pres_def_presentation",
]
