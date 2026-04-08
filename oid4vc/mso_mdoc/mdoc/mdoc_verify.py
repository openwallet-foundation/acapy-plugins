"""Standalone mDOC issuer-signature verification helper."""

import logging
from typing import List, Optional

import isomdl_uniffi

from .cred_verifier import _parse_string_credential
from .utils import flatten_trust_anchors

LOGGER = logging.getLogger(__name__)


class MdocVerifyResult:
    """Result of mdoc verification."""

    def __init__(
        self,
        verified: bool,
        payload: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        """Initialize the verification result."""
        self.verified = verified
        self.payload = payload
        self.error = error

    def serialize(self):
        """Serialize the result to a dictionary."""
        return {
            "verified": self.verified,
            "payload": self.payload,
            "error": self.error,
        }


def mdoc_verify(
    mso_mdoc: str, trust_anchors: Optional[List[str]] = None
) -> MdocVerifyResult:
    """Verify an mso_mdoc credential.

    Accepts mDOC strings in any format understood by ``_parse_string_credential``:
    hex-encoded DeviceResponse, base64url IssuerSigned, or raw base64.

    Args:
        mso_mdoc: The mDOC string (hex, base64url, or base64).
        trust_anchors: Optional list of PEM-encoded trust anchor certificates.
            Each element may contain a single cert or a concatenated PEM chain;
            chains are automatically split before being passed to Rust.

    Returns:
        MdocVerifyResult: The verification result.
    """
    try:
        # Parse the mdoc — try all supported formats
        mdoc, parse_error = _parse_string_credential(mso_mdoc)
        if not mdoc:
            return MdocVerifyResult(
                verified=False,
                error=f"Failed to parse mDOC: {parse_error or 'unknown format'}",
            )

        # Flatten concatenated PEM chains so Rust receives one cert per list
        # entry (isomdl_uniffi only reads the first PEM block in a string).
        if trust_anchors:
            trust_anchors = flatten_trust_anchors(trust_anchors)

        # Fail-closed guard: refuse to verify without at least one trust anchor.
        if not trust_anchors:
            return MdocVerifyResult(
                verified=False,
                error="No trust anchors configured; mDOC verification requires "
                "at least one trust anchor.",
            )

        # Verify issuer signature
        try:
            # Enable intermediate certificate chaining by default
            verification_result = mdoc.verify_issuer_signature(trust_anchors, True)

            if verification_result.verified:
                return MdocVerifyResult(
                    verified=True,
                    payload={
                        "status": "verified",
                        "doctype": mdoc.doctype(),
                        "issuer_common_name": verification_result.common_name,
                    },
                )
            else:
                return MdocVerifyResult(
                    verified=False,
                    payload={"doctype": mdoc.doctype()},
                    error=verification_result.error or "Signature verification failed",
                )
        except isomdl_uniffi.MdocVerificationError as e:
            return MdocVerifyResult(
                verified=False,
                payload={"doctype": mdoc.doctype()},
                error=str(e),
            )

    except Exception as e:
        return MdocVerifyResult(verified=False, error=str(e))
