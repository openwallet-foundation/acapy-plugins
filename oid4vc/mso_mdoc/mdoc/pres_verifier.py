"""mso_mdoc OID4VP presentation verifier."""

import json
import logging
from typing import Any, List, Optional

import isomdl_uniffi
from acapy_agent.core.profile import Profile
from cryptography import x509 as _x509

from oid4vc.config import Config
from oid4vc.cred_processor import PresVerifier, VerifyResult
from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.models.presentation import OID4VPPresentation

from .utils import check_status_list_claim, flatten_trust_anchors
from .cred_verifier import PreverifiedMdocClaims
from .mdoc_item import (
    _decode_presentation_bytes,
    _normalize_presentation_input,
    extract_verified_claims,
)

LOGGER = logging.getLogger(__name__)


async def _get_oid4vp_verification_params(
    profile: Profile,
    presentation_record: "OID4VPPresentation",
) -> tuple[str, str, str]:
    """Get OID4VP verification parameters.

    Args:
        profile: The profile
        presentation_record: The presentation record

    Returns:
        Tuple of (nonce, client_id, response_uri)
    """
    nonce = presentation_record.nonce
    config = Config.from_settings(profile.settings)

    async with profile.session() as session:
        jwk = await retrieve_or_create_did_jwk(session)

    client_id = jwk.did

    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    response_uri = (
        f"{config.endpoint}{subpath}/oid4vp/response/"
        f"{presentation_record.presentation_id}"
    )

    return nonce, client_id, response_uri


def _verify_single_presentation(
    response_bytes: bytes,
    nonce: str,
    client_id: str,
    response_uri: str,
    trust_anchor_registry: List[str],
) -> Any:
    """Verify a single OID4VP presentation.

    Args:
        response_bytes: The presentation bytes
        nonce: The nonce
        client_id: The client ID
        response_uri: The response URI
        trust_anchor_registry: JSON-serialized PemTrustAnchor strings, each of the form
            '{"certificate_pem": "...", "purpose": "Iaca"}'

    Returns:
        Verified payload dict if successful, None if failed
    """
    LOGGER.debug(
        "Calling verify_oid4vp_response with: "
        "nonce=%s client_id=%s response_uri=%s "
        "response_bytes_len=%d",
        nonce,
        client_id,
        response_uri,
        len(response_bytes),
    )

    # Try spec-compliant format (2024) first
    verified_data = isomdl_uniffi.verify_oid4vp_response(
        response_bytes,
        nonce,
        client_id,
        response_uri,
        trust_anchor_registry,
        True,
    )

    # If device auth failed but issuer is valid, try legacy format
    if (
        verified_data.device_authentication != isomdl_uniffi.AuthenticationStatus.VALID
        and verified_data.issuer_authentication
        == isomdl_uniffi.AuthenticationStatus.VALID
    ):
        if hasattr(isomdl_uniffi, "verify_oid4vp_response_legacy"):
            LOGGER.info(
                "Device auth failed with spec-compliant format, trying legacy 2023 format"
            )
            verified_data = isomdl_uniffi.verify_oid4vp_response_legacy(
                response_bytes,
                nonce,
                client_id,
                response_uri,
                trust_anchor_registry,
                True,
            )
        else:
            LOGGER.warning(
                "Device auth failed and legacy format not available in isomdl_uniffi"
            )

    return verified_data


class MsoMdocPresVerifier(PresVerifier):
    """Verifier for mso_mdoc presentations (OID4VP)."""

    def __init__(self, trust_anchors: Optional[List[str]] = None):
        """Initialize the presentation verifier.

        Args:
            trust_anchors: PEM-encoded trust anchor certificates.
        """
        self.trust_anchors = trust_anchors or []

    def _parse_jsonpath(self, path: str) -> List[str]:
        """Parse JSONPath to extract segments."""
        # Handle $['namespace']['element'] format
        if "['" in path:
            return [
                p.strip("]['\"")
                for p in path.split("['")
                if p.strip("]['\"") and p != "$"
            ]

        # Handle $.namespace.element format
        clean = path.replace("$", "")
        if clean.startswith("."):
            clean = clean[1:]
        return clean.split(".")

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify an mso_mdoc presentation.

        Args:
            profile: The profile for context
            presentation: The presentation data (bytes)
            presentation_record: The presentation record containing request info

        Returns:
            VerifyResult: The verification result
        """
        try:
            # 1. Prepare Trust Anchors
            trust_anchors = (
                flatten_trust_anchors(self.trust_anchors) if self.trust_anchors else []
            )
            LOGGER.debug(
                "Trust anchors loaded: %d cert(s)",
                len(trust_anchors),
            )
            for i, pem in enumerate(trust_anchors):
                pem_stripped = pem.strip() if pem else ""
                LOGGER.debug(
                    "Trust anchor %d: len=%d",
                    i,
                    len(pem_stripped),
                )
                # Validate that the PEM is parseable by Python before
                # passing to Rust
                try:
                    _x509.load_pem_x509_certificate(pem_stripped.encode())
                except Exception as pem_err:
                    LOGGER.error(
                        "Trust anchor %d: PEM validation FAILED: %s",
                        i,
                        pem_err,
                    )

            if trust_anchors:
                LOGGER.debug(
                    "Trust anchors after chain-splitting: %d individual cert(s)",
                    len(trust_anchors),
                )

            # Fail-closed guard: refuse to verify without at least one trust
            # anchor.  An empty list causes Rust to accept any self-signed
            # issuer certificate, bypassing chain validation entirely.
            if not trust_anchors:
                return VerifyResult(
                    verified=False,
                    payload={
                        "error": "No trust anchors configured; presentation "
                        "verification requires at least one trust anchor."
                    },
                )

            # verify_oid4vp_response expects JSON-serialized PemTrustAnchor per anchor:
            # {"certificate_pem": "...", "purpose": "Iaca"}
            # Rust parses each string via serde_json::from_str::<PemTrustAnchor>().
            trust_anchor_registry = (
                [
                    json.dumps({"certificate_pem": pem, "purpose": "Iaca"})
                    for pem in trust_anchors
                ]
                if trust_anchors
                else []
            )
            if trust_anchor_registry:
                LOGGER.debug(
                    "trust_anchor_registry[0] first100: %r",
                    trust_anchor_registry[0][:100],
                )

            # 2. Get verification parameters
            nonce, client_id, response_uri = await _get_oid4vp_verification_params(
                profile, presentation_record
            )

            # 3. Normalize presentation input
            presentations_to_verify, is_list_input = _normalize_presentation_input(
                presentation
            )

            verified_payloads = []

            for pres_item in presentations_to_verify:
                LOGGER.debug(
                    "vp_token type=%s len=%s",
                    type(pres_item).__name__,
                    len(pres_item) if hasattr(pres_item, "__len__") else "N/A",
                )

                response_bytes = _decode_presentation_bytes(pres_item)

                verified_data = _verify_single_presentation(
                    response_bytes,
                    nonce,
                    client_id,
                    response_uri,
                    trust_anchor_registry,
                )

                # Per ISO 18013-5, deviceSigned is optional (marked with '?' in
                # the CDDL).  For OID4VP web-wallet flows a device key binding
                # round-trip is not performed, so device_authentication will not
                # be VALID.  Issuer authentication is sufficient to trust that
                # the credential was issued by a known authority.
                issuer_ok = (
                    verified_data.issuer_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )
                device_ok = (
                    verified_data.device_authentication
                    == isomdl_uniffi.AuthenticationStatus.VALID
                )

                if issuer_ok:
                    if not device_ok:
                        LOGGER.info(
                            "Device authentication not present/valid (issuer-only "
                            "OID4VP presentation — deviceSigned is optional per "
                            "ISO 18013-5): Device=%s",
                            verified_data.device_authentication,
                        )
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
                    except Exception as e:
                        LOGGER.warning("Failed to extract claims: %s", e)
                        claims = {}

                    # Check IETF Token Status List revocation if embedded in claims
                    revocation_error = await check_status_list_claim(claims)
                    if revocation_error:
                        LOGGER.warning(
                            "mDoc presentation rejected — credential revoked: %s",
                            revocation_error,
                        )
                        return VerifyResult(
                            verified=False,
                            payload={
                                "error": revocation_error,
                                "docType": verified_data.doc_type,
                            },
                        )

                    payload = {
                        "status": "verified",
                        "docType": verified_data.doc_type,
                        "issuer_auth": str(verified_data.issuer_authentication),
                        "device_auth": str(verified_data.device_authentication),
                    }
                    payload.update(claims)
                    verified_payloads.append(PreverifiedMdocClaims(claims=payload))
                else:
                    LOGGER.error(
                        "Verification failed: Issuer=%s, Device=%s, Errors=%s",
                        verified_data.issuer_authentication,
                        verified_data.device_authentication,
                        verified_data.errors,
                    )
                    try:
                        claims = extract_verified_claims(verified_data.verified_response)
                    except Exception:
                        claims = {}

                    return VerifyResult(
                        verified=False,
                        payload={
                            "error": verified_data.errors,
                            "issuer_auth": str(verified_data.issuer_authentication),
                            "device_auth": str(verified_data.device_authentication),
                            "claims": claims,
                        },
                    )

            # Return list if input was list, otherwise single item
            payload = verified_payloads
            if not is_list_input and len(verified_payloads) == 1:
                payload = verified_payloads[0]

            return VerifyResult(verified=True, payload=payload)

        except Exception as e:
            LOGGER.exception("Error verifying mdoc presentation")
            return VerifyResult(verified=False, payload={"error": str(e)})
