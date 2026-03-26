"""Helper utilities for OID4VC integration tests.

This package provides reusable components for DRY test implementation:
- constants: Enums and constant values
- assertions: Custom assertion functions
- flow_helpers: High-level flow orchestration
- utils: Polling, waiting, and miscellaneous utilities
"""

from .assertions import (
    assert_credential_revoked,
    assert_disclosed_claims,
    assert_hidden_claims,
    assert_mdoc_structure,
    assert_presentation_successful,
    assert_selective_disclosure,
    assert_valid_sd_jwt,
)
from .constants import (
    ALGORITHMS,
    MDL_MANDATORY_FIELDS,
    MDOC_AVAILABLE,
    TEST_CONFIG,
    VCT,
    CredentialFormat,
    Doctype,
    mdl,
)
from .flow_helpers import CredentialFlowHelper, PresentationFlowHelper
from .utils import (
    assert_claims_absent,
    assert_claims_present,
    wait_for_presentation_state,
)

__all__ = [
    # Constants
    "CredentialFormat",
    "Doctype",
    "MDL_MANDATORY_FIELDS",
    "VCT",
    "ALGORITHMS",
    "MDOC_AVAILABLE",
    "TEST_CONFIG",
    "mdl",
    # Assertions
    "assert_disclosed_claims",
    "assert_hidden_claims",
    "assert_selective_disclosure",
    "assert_valid_sd_jwt",
    "assert_mdoc_structure",
    "assert_presentation_successful",
    "assert_credential_revoked",
    # Flow helpers
    "CredentialFlowHelper",
    "PresentationFlowHelper",
    # Utils
    "assert_claims_present",
    "assert_claims_absent",
    "wait_for_presentation_state",
]
