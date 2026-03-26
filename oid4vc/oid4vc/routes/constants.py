"""Constants for admin API routes."""

import logging

# OpenID4VCI 1.0 Final Specification
# https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
VCI_SPEC_URI = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
VP_SPEC_URI = "https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html"

LOGGER = logging.getLogger(__name__)
CODE_BYTES = 16
