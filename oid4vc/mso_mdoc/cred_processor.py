"""mso_mdoc credential processor.

Glues together the signing-key resolution, payload preparation, and isomdl
binding layers to implement ISO/IEC 18013-5:2021 compliant mDoc issuance and
verification inside the OID4VCI plugin framework.
"""

import base64
import json
import logging
import re
from datetime import UTC, datetime

from cryptography import x509 as _x509
from typing import Any, Dict, List, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import CredProcessorError, CredVerifier, Issuer, PresVerifier
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .mdoc.issuer import MDL_MANDATORY_FIELDS, isomdl_mdoc_sign
from .mdoc.cred_verifier import MsoMdocCredVerifier
from .mdoc.pres_verifier import MsoMdocPresVerifier
from .payload import normalize_mdoc_result, prepare_mdoc_payload
from .trust_anchor import TrustAnchorRecord
from .signing_key import MdocSigningKeyRecord

__all__ = [
    "MsoMdocCredProcessor",
    "check_certificate_not_expired",
]

LOGGER = logging.getLogger(__name__)


def check_certificate_not_expired(cert_pem: str) -> None:
    """Validate that a PEM-encoded X.509 certificate is currently valid."""
    if not cert_pem or not cert_pem.strip():
        raise CredProcessorError("Empty certificate PEM string")

    try:
        cert = _x509.load_pem_x509_certificate(cert_pem.strip().encode())
    except Exception as exc:
        raise CredProcessorError(
            f"Invalid certificate PEM — could not parse: {exc}"
        ) from exc

    now = datetime.now(UTC)
    if cert.not_valid_before_utc > now:
        nb = cert.not_valid_before_utc.isoformat()
        raise CredProcessorError(f"Certificate is not yet valid (NotBefore={nb})")
    if cert.not_valid_after_utc < now:
        na = cert.not_valid_after_utc.isoformat()
        raise CredProcessorError(f"Certificate has expired (NotAfter={na})")


async def _get_trust_anchors(
    profile: Profile,
    doctype: Optional[str] = None,
) -> List[str]:
    """Collect trust anchor PEMs from TrustAnchorRecord storage.

    Queries ``TrustAnchorRecord`` records with ``purpose="iaca"``.  When
    *doctype* is provided, records whose ``doctype`` tag matches OR whose
    ``doctype`` tag is ``None`` ("wildcard") are both included.
    """
    anchors: List[str] = []

    async with profile.session() as session:
        records = await TrustAnchorRecord.query(session, tag_filter={"purpose": "iaca"})
        for record in records:
            # When doctype is unspecified, include all anchors (no filtering).
            # When doctype is specified, include only exact matches and wildcards
            # (records stored without a doctype that apply to all credential types).
            if doctype is None or record.doctype is None or record.doctype == doctype:
                if record.certificate_pem:
                    anchors.append(record.certificate_pem)

    return anchors


class MsoMdocCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for mso_mdoc credential format."""

    # COSE algorithm name → integer identifier mapping (RFC 8152 / IANA COSE registry)
    _COSE_ALG: dict = {"ES256": -7, "ES384": -35, "ES512": -36, "ES256K": -47}

    def credential_metadata(self, supported_cred: dict) -> dict:
        """Shape issuer metadata for mso_mdoc format.

        Lifts ``doctype`` from ``format_data`` to the top level, converts the
        namespace-keyed claims dict to the spec-compliant flat array, moves
        ``display`` into ``credential_metadata``, and converts COSE algorithm
        string names to integer identifiers per OID4VCI 1.0 / ISO 18013-5.
        """
        format_data = supported_cred.pop("format_data", None) or {}
        supported_cred.pop("vc_additional_data", None)  # trust anchors etc. are internal

        doctype = format_data.get("doctype")
        claims = format_data.get("claims")

        # Convert COSE algorithm string names to integer identifiers
        # (e.g. "ES256" → -7).  Numeric strings ("-7") are already converted
        # by to_issuer_metadata(); this handles name-form values like "ES256".
        algs = supported_cred.get("credential_signing_alg_values_supported")
        if algs:
            supported_cred["credential_signing_alg_values_supported"] = [
                self._COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
            ]

        # Convert namespace-keyed claims dict to flat path-array per OID4VCI spec
        if isinstance(claims, dict):
            claims_list = []
            for namespace, claim_map in claims.items():
                if isinstance(claim_map, dict):
                    for claim_name, descriptor in claim_map.items():
                        entry: dict = {"path": [namespace, claim_name]}
                        if isinstance(descriptor, dict):
                            if "mandatory" in descriptor:
                                entry["mandatory"] = descriptor["mandatory"]
                            if "display" in descriptor:
                                entry["display"] = descriptor["display"]
                        claims_list.append(entry)
            claims = claims_list

        if claims:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["claims"] = claims

        # Move top-level display into credential_metadata per OID4VCI 1.0 §12.2.4
        display = supported_cred.pop("display", None)
        if display is not None:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["display"] = display

        if doctype:
            return {"doctype": doctype, **supported_cred}
        return supported_cred

    def __init__(self):
        """Initialize the processor."""

    def _validate_and_get_doctype(
        self, body: Dict[str, Any], supported: SupportedCredential
    ) -> str:
        """Validate and extract doctype from request and configuration.

        Validates the document type identifier according to ISO 18013-5 § 8.3.2.1.2.1
        requirements and OpenID4VCI 1.0 § E.1.1 specification.

        Args:
            body: Request body containing credential issuance parameters
            supported: Supported credential configuration with format data

        Returns:
            Validated doctype string (e.g., "org.iso.18013.5.1.mDL")

        Raises:
            CredProcessorError: If doctype validation fails with detailed context
        """
        doctype_from_request = body.get("doctype")
        doctype_from_config = (
            supported.format_data.get("doctype") if supported.format_data else None
        )

        if not doctype_from_request and not doctype_from_config:
            raise CredProcessorError(
                "Document type (doctype) is required for mso_mdoc format. "
                "Provide doctype in request body or credential configuration. "
                "See OpenID4VCI 1.0 § E.1.1 and ISO 18013-5 § 8.3.2.1.2.1"
            )

        # Use doctype from request if provided, otherwise from configuration
        doctype = doctype_from_request or doctype_from_config

        if doctype_from_request and doctype_from_config:
            if doctype_from_request != doctype_from_config:
                raise CredProcessorError(
                    f"Document type mismatch: request contains '{doctype_from_request}' "
                    f"but credential configuration specifies '{doctype_from_config}'. "
                    "Ensure consistency between request and credential configuration."
                )

        # Validate doctype format (basic ISO format check)
        if not doctype or not isinstance(doctype, str):
            raise CredProcessorError(
                "Invalid doctype format: expected non-empty string, "
                f"got {type(doctype).__name__}"
            )

        if not doctype.startswith("org.iso."):
            LOGGER.warning(
                "Document type '%s' does not follow ISO format convention (org.iso.*)",
                doctype,
            )

        return doctype

    def _extract_device_key(
        self, pop: PopResult, ex_record: OID4VCIExchangeRecord
    ) -> Optional[str]:
        """Extract device authentication key from proof of possession or exchange record.

        Extracts and validates the device key for holder binding according to
        ISO 18013-5 § 9.1.3.4 device authentication requirements and
        OpenID4VCI proof of possession mechanisms.

        Args:
            pop: Proof of possession result containing holder key information
            ex_record: Exchange record with credential issuance context

        Returns:
            Serialized device key string (JWK JSON or key identifier),
            or None if unavailable

        Raises:
            CredProcessorError: If device key format is invalid or unsupported
        """
        # Priority order: holder JWK > holder key ID > verification method from record
        device_candidate = (
            pop.holder_jwk or pop.holder_kid or ex_record.verification_method
        )

        if isinstance(device_candidate, dict):
            # The device key embedded in the mDoc MSO must contain ONLY public
            # parameters; passing 'd' to the Rust isomdl library would leak
            # the holder's private key into the issued credential.
            _PUBLIC_JWK_FIELDS = frozenset(("kty", "crv", "x", "y", "n", "e"))
            public_only = {
                k: v for k, v in device_candidate.items() if k in _PUBLIC_JWK_FIELDS
            }
            return json.dumps(public_only)
        elif isinstance(device_candidate, str):
            # If a DID with fragment, prefer fragment (key id); otherwise raw string
            m = re.match(r"did:(.+?):(.+?)(?:#(.*))?$", device_candidate)
            if m:
                method = m.group(1)
                identifier = m.group(2)
                fragment = m.group(3)

                if method == "jwk":
                    # did:jwk encodes the holder's public JWK as a base64url
                    # value in the DID identifier itself (i.e. between
                    # "did:jwk:" and "#0").  ACA-Py uses this method natively
                    # when a wallet generates ephemeral keys.
                    #
                    # Without special handling the generic DID regex returns
                    # only the fragment "0", and json.loads("0") silently
                    # produces the integer 0 — which the Rust isomdl library
                    # then receives as the holder key, causing an opaque
                    # failure with no hint that the root cause is a
                    # mis-parsed DID method.
                    try:
                        # Base64url may be missing padding — add it back.
                        padding = "=" * (-len(identifier) % 4)
                        jwk_bytes = base64.urlsafe_b64decode(identifier + padding)
                        return jwk_bytes.decode("utf-8")
                    except Exception as exc:
                        raise CredProcessorError(
                            f"Invalid did:jwk identifier — could not decode "
                            f"embedded JWK from '{device_candidate}': {exc}"
                        ) from exc

                return fragment if fragment else device_candidate
            else:
                return device_candidate

        return None

    def _build_headers(
        self, doctype: str, device_key_str: Optional[str]
    ) -> Dict[str, Any]:
        """Build mso_mdoc headers according to OID4VCI specification."""
        headers = {"doctype": doctype}
        if device_key_str:
            headers["deviceKey"] = device_key_str
        return headers

    async def _resolve_signing_key(
        self,
        supported: SupportedCredential,
        profile: Optional[Profile] = None,
    ) -> Dict[str, Any]:
        """Resolve the signing key for credential issuance.

        Resolution order:
        1. ``signing_key_id`` in ``vc_additional_data`` — fetch a specific
           ``MdocSigningKeyRecord`` by ID.
        2. ``MdocSigningKeyRecord`` query by doctype — first matching record.

        Returns:
            Dict with ``private_key_pem`` and ``certificate_pem``.
        """
        additional = supported.vc_additional_data or {}
        doctype = (supported.format_data or {}).get("doctype")

        # 1. Explicit signing key record ID
        signing_key_id = additional.get("signing_key_id")
        if signing_key_id and profile:
            try:
                async with profile.session() as session:
                    key_record = await MdocSigningKeyRecord.retrieve_by_id(
                        session, signing_key_id
                    )
                if key_record.private_key_pem and key_record.certificate_pem:
                    return {
                        "private_key_pem": key_record.private_key_pem,
                        "certificate_pem": key_record.certificate_pem,
                    }
            except Exception as exc:
                LOGGER.warning(
                    "Could not load MdocSigningKeyRecord %s: %s", signing_key_id, exc
                )

        # 2. MdocSigningKeyRecord query by doctype (or any key if no doctype)
        if profile:
            try:
                async with profile.session() as session:
                    tag_filter = {"doctype": doctype} if doctype else None
                    key_records = await MdocSigningKeyRecord.query(
                        session, tag_filter=tag_filter
                    )
                    if not key_records and doctype:
                        # fall back to wildcard keys (no doctype set)
                        key_records = await MdocSigningKeyRecord.query(session)
                    for key_record in key_records:
                        if key_record.private_key_pem and key_record.certificate_pem:
                            return {
                                "private_key_pem": key_record.private_key_pem,
                                "certificate_pem": key_record.certificate_pem,
                            }
            except Exception as exc:
                LOGGER.debug("MdocSigningKeyRecord query failed: %s", exc)

        raise CredProcessorError(
            "No mDoc signing key configured. "
            "Create a MdocSigningKeyRecord via POST /mso-mdoc/signing-keys."
        )

    async def _assign_status_entry(
        self,
        context: AdminRequestContext,
        supported: SupportedCredential,
        doctype: str,
    ) -> Optional[Dict[str, Any]]:
        """Optionally assign a Token Status List entry for the credential.

        If ``status_list_def_id`` and ``status_list_base_uri`` are set in the
        ``SupportedCredential.vc_additional_data``, this method attempts to
        assign an entry from the status_list plugin and returns the status
        claim dict to embed in the payload.

        Returns ``None`` if the status list plugin is not installed or not
        configured for this credential type.
        """
        additional = supported.vc_additional_data or {}
        definition_id = additional.get("status_list_def_id")
        base_uri = (additional.get("status_list_base_uri") or "").rstrip("/")

        if not definition_id or not base_uri:
            return None

        try:
            from status_list.status_list.v1_0 import (  # noqa: PLC0415
                status_handler as _status_handler,
            )
        except ImportError:
            LOGGER.debug(
                "status_list plugin not installed; skipping revocation entry assignment"
            )
            return None

        try:
            entry = await _status_handler.assign_status_list_entry(context, definition_id)
        except Exception as exc:
            LOGGER.warning(
                "Failed to assign status list entry for definition %s: %s",
                definition_id,
                exc,
            )
            return None

        if entry is None:
            LOGGER.warning(
                "Status list entry assignment returned None for definition %s",
                definition_id,
            )
            return None

        list_number = entry.get("list_number", "")
        list_index = entry.get("list_index", 0)
        status_uri = f"{base_uri}/{list_number}"

        LOGGER.info(
            "Assigned status list entry: doctype=%s list_number=%s index=%d uri=%s",
            doctype,
            list_number,
            list_index,
            status_uri,
        )

        return {"status_list": {"idx": list_index, "uri": status_uri}}

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in CBOR format.

        Issues an ISO 18013-5 compliant mDoc credential using the mobile
        security object (MSO) format. The credential is CBOR-encoded and
        follows the issuerSigned structure defined in ISO 18013-5.

        Protocol Compliance:
        - OpenID4VCI 1.0 § 7.3.1: Credential Response for mso_mdoc format
        - OpenID4VCI 1.0 Appendix E.1.1: mso_mdoc Credential format identifier
        - ISO 18013-5 § 8.3: Mobile document structure
        - ISO 18013-5 § 9.1.2: IssuerSigned data structure
        - ISO 18013-5 § 9.1.3: Mobile security object (MSO)
        - RFC 8949: CBOR encoding for binary efficiency
        - RFC 8152: COSE signing for cryptographic protection

        OpenID4VCI 1.0 § E.1.1: mso_mdoc Format
        https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
        """
        if not supported.format_data:
            raise CredProcessorError("Supported credential must have format_data")

        try:
            # Validate and extract doctype
            doctype = self._validate_and_get_doctype(body, supported)

            # Extract device key for holder binding
            device_key_str = self._extract_device_key(pop, ex_record)

            # Build mso_mdoc headers
            headers = self._build_headers(doctype, device_key_str)

            # Get payload
            payload = prepare_mdoc_payload(ex_record.credential_subject, doctype)

            # Optionally assign a status list entry and embed the status claim
            status_claim = await self._assign_status_entry(context, supported, doctype)
            if status_claim:
                payload["status"] = status_claim

            # Resolve signing key — check MdocSigningKeyRecord first, then
            # fall back to vc_additional_data and env vars
            key_data = await self._resolve_signing_key(supported, context.profile)
            private_key_pem = key_data["private_key_pem"]
            certificate_pem = key_data["certificate_pem"]

            # Validity-period guard: reject expired or not-yet-valid certificates
            # before passing them to the Rust signing library.
            check_certificate_not_expired(certificate_pem)

            if not device_key_str and not pop.holder_jwk:
                raise CredProcessorError(
                    "No device key available: provide holder_jwk, "
                    "holder_kid, or verification_method"
                )

            # Clean up JWK for isomdl (remove extra fields like kid, alg, use)
            # isomdl rejects alg and use fields in the holder JWK
            if pop.holder_jwk and isinstance(pop.holder_jwk, dict):
                if pop.holder_jwk.get("kty") != "EC":
                    raise CredProcessorError(
                        "mso_mdoc requires an EC holder key, "
                        f"got kty={pop.holder_jwk.get('kty')}"
                    )
                holder_jwk_clean = {
                    k: v
                    for k, v in pop.holder_jwk.items()
                    if k in ["kty", "crv", "x", "y"]
                }
            else:
                # Fallback: build a minimal JWK placeholder from device_key_str
                # The Rust library needs a JWK dict for the holder key binding
                holder_jwk_clean = None

            # Issue mDoc using isomdl-uniffi library with ISO 18013-5 compliance
            LOGGER.debug(
                "Issuing mso_mdoc with holder_jwk=%s headers=%s payload_keys=%s",
                holder_jwk_clean,
                headers,
                (list(payload.keys()) if isinstance(payload, dict) else type(payload)),
            )
            # Use cleaned JWK if available, otherwise fall back to
            # the device key extracted from holder_kid / verification_method.
            # isomdl_mdoc_sign expects a dict-like JWK.
            signing_holder_key = holder_jwk_clean
            if signing_holder_key is None and device_key_str:
                try:
                    signing_holder_key = json.loads(device_key_str)
                except (json.JSONDecodeError, TypeError):
                    # device_key_str is a key-id, not a JWK —
                    # cannot bind holder key without a JWK.
                    raise CredProcessorError(
                        "Holder key identifier provided but a full "
                        "EC JWK is required for mso_mdoc device "
                        "key binding. Provide holder_jwk in the "
                        "proof of possession."
                    )

            if signing_holder_key is None:
                raise CredProcessorError(
                    "Unable to resolve a holder JWK for device key binding."
                )

            mso_mdoc = isomdl_mdoc_sign(
                signing_holder_key, headers, payload, certificate_pem, private_key_pem
            )

            # Normalize mDoc result handling for robust string/bytes processing
            mso_mdoc = normalize_mdoc_result(mso_mdoc)

            LOGGER.info(
                "Issued mso_mdoc credential with doctype: %s, format: %s",
                doctype,
                supported.format,
            )

        except Exception as ex:
            # Log full exception for debugging before raising a generic error
            LOGGER.exception("mso_mdoc issuance error: %s", ex)
            # Surface the underlying exception text in the CredProcessorError
            raise CredProcessorError(f"Failed to issue mso_mdoc credential: {ex}") from ex

        # issuer_signed_b64() already returns base64url without padding
        # (ISO 18013-5 §8.3 compliant) — exactly what OID4VCI 1.0 §7.3.1 requires.
        LOGGER.debug("mso_mdoc credential: %s", mso_mdoc)

        return mso_mdoc

    def _prepare_payload(
        self, payload: Dict[str, Any], doctype: str = None
    ) -> Dict[str, Any]:
        return prepare_mdoc_payload(payload, doctype)

    def _normalize_mdoc_result(self, result: Any) -> str:
        return normalize_mdoc_result(result)

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        if not subject:
            raise CredProcessorError("Credential subject cannot be empty")

        if not isinstance(subject, dict):
            raise CredProcessorError("Credential subject must be a dictionary")

        # For mDL doctypes, validate mandatory ISO 18013-5 fields early so
        # that the API caller gets an actionable error at exchange-creation
        # time rather than an opaque FFI error at issuance time.
        doctype = (supported.format_data or {}).get("doctype", "")
        if doctype == "org.iso.18013.5.1.mDL":
            # The subject may be namespace-wrapped or flat.
            claims = subject.get("org.iso.18013.5.1", subject)
            # driving_privileges defaults to [] at issuance time, so
            # exclude it from the early check.
            missing = [
                f
                for f in MDL_MANDATORY_FIELDS
                if f != "driving_privileges" and f not in claims
            ]
            if missing:
                raise CredProcessorError(
                    f"mDL credential_subject is missing mandatory ISO 18013-5 "
                    f"data element(s): {', '.join(missing)}"
                )

        return True

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        if not supported.format_data:
            raise CredProcessorError("format_data is required for mso_mdoc format")

        # Validate doctype presence and format
        self._validate_and_get_doctype({}, supported)

        return True

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ):
        """Verify an mso_mdoc credential."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocCredVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_credential(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: "OID4VPPresentation",
    ):
        """Verify an mso_mdoc presentation."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocPresVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_presentation(
            profile, presentation, presentation_record
        )
