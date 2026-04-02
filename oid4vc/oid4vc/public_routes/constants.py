"""Constants for public routes (OID4VCI token endpoint)."""

import logging

LOGGER = logging.getLogger(__name__)

# OAuth 2.0 grant type for pre-authorized code flow
# https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

# Number of random bytes for nonce generation
NONCE_BYTES = 16

# Token expiration time in seconds (24 hours)
EXPIRES_IN = 86400
