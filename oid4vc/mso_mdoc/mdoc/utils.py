"""Utility functions for mso_mdoc credential operations."""

import base64
import json as _json
import logging
import re
import zlib
from typing import List, Optional

LOGGER = logging.getLogger(__name__)


# Matches a single complete PEM certificate block (including its trailing newline, if any)
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\n?",
    re.DOTALL,
)


def split_pem_chain(pem_chain: str) -> List[str]:
    r"""Split a concatenated PEM chain into individual certificate PEM strings.

    The isomdl-uniffi Rust library (and the underlying x509_cert crate) reads
    only the **first** ``-----BEGIN CERTIFICATE-----`` block from a PEM string.
    When a caller stores or passes a multi-cert chain as one string, every cert
    after the first is silently dropped, causing either:

    * **Issuer side** – the wrong certificate is embedded in the MSO (the
      signing key no longer corresponds to the embedded cert → verification
      fails).
    * **Verifier side** – trust-anchor chains are truncated to one cert, so
      any mdoc whose embedded cert is not the single root in the chain cannot
      be verified.

    This function normalises any PEM input into a flat list of single-cert
    PEM strings so that each element can be safely handed to Rust.

    Args:
        pem_chain: Zero or more PEM certificate blocks, possibly concatenated
            with arbitrary whitespace between them.

    Returns:
        List of individual PEM certificate strings, one cert per element.
        Returns an empty list for blank / whitespace-only input.

    Examples::

        # Single cert → one-element list (no-op)
        split_pem_chain(single_cert_pem)  # ["-----BEGIN CERTIFICATE-----\n..."]

        # Root + leaf chain → two-element list
        split_pem_chain(root_pem + leaf_pem)  # [root_pem, leaf_pem]
    """
    if not pem_chain or not pem_chain.strip():
        return []

    matches = _PEM_CERT_RE.findall(pem_chain)
    return matches


def extract_signing_cert(pem_chain: str) -> str:
    """Return the first certificate from a PEM chain.

    For the issuer, the signing certificate (the one whose private key is
    used to sign the MSO) is expected to be the **first** cert in the chain.
    This helper extracts exactly that cert so that only one PEM block is
    forwarded to ``Mdoc.create_and_sign()``.

    Args:
        pem_chain: One or more concatenated PEM certificate blocks.

    Returns:
        PEM string containing only the first certificate in the chain.

    Raises:
        ValueError: If no certificate block is found in *pem_chain*.
    """
    certs = split_pem_chain(pem_chain)
    if not certs:
        raise ValueError(
            "No certificate found in provided PEM string. "
            "Expected at least one '-----BEGIN CERTIFICATE-----' block."
        )
    return certs[0]


def flatten_trust_anchors(trust_anchors: List[str]) -> List[str]:
    """Flatten a list of PEM trust-anchor strings into individual cert PEMs.

    Each element of *trust_anchors* may itself contain a concatenated PEM
    chain.  This function expands every element so that the returned list
    contains one entry per individual certificate, which is what the Rust
    ``verify_issuer_signature`` / ``verify_oid4vp_response`` APIs expect.

    Args:
        trust_anchors: List of PEM strings, each potentially containing
            multiple concatenated certificate blocks.

    Returns:
        Flat list of single-certificate PEM strings.
    """
    flat: List[str] = []
    for pem in trust_anchors:
        flat.extend(split_pem_chain(pem))
    return flat


async def check_status_list_claim(claims: dict) -> Optional[str]:
    """Check IETF Token Status List revocation status embedded in mDoc claims.

    Searches all namespaces in *claims* for a ``status.status_list`` entry
    containing ``idx`` (credential index) and ``uri`` (status list endpoint).
    If found, fetches the published status list JWT, decodes the little-endian
    compressed bitstring, and checks the bit(s) at *idx*.

    Per IETF Token Status List draft:
    - ``status_list.lst``: base64url-encoded, zlib-compressed little-endian bitstring
    - ``status_list.bits``: number of bits per credential entry (typically 1)
    - A non-zero value at position *idx* means the credential is revoked/suspended.

    Args:
        claims: Namespace-keyed claims dict from ``extract_verified_claims`` or
                ``_extract_mdoc_claims``, e.g.
                ``{"org.iso.18013.5.1": {"family_name": "Smith", "status": {...}}}``

    Returns:
        ``None`` if the credential is valid (or has no status claim).
        An error string if the credential is revoked or suspended.
    """
    # Search all namespaces for a status.status_list.{idx, uri} entry
    status_entry = None
    for ns_claims in claims.values():
        if not isinstance(ns_claims, dict):
            continue
        status = ns_claims.get("status")
        if isinstance(status, dict) and "status_list" in status:
            status_entry = status["status_list"]
            break

    if not status_entry:
        return None  # No revocable status claim → credential is valid

    idx = status_entry.get("idx")
    uri = status_entry.get("uri")

    if idx is None or not uri:
        LOGGER.warning(
            "Malformed status_list claim — missing idx or uri; skipping revocation check"
        )
        return None

    # Fetch the published status list JWT
    try:
        import aiohttp  # noqa: PLC0415 — imported lazily to keep utils lean

        async with aiohttp.ClientSession() as http:
            async with http.get(uri) as resp:
                resp.raise_for_status()
                jwt_text = await resp.text()
    except Exception as exc:
        LOGGER.warning(
            "Could not fetch status list from %r — revocation check skipped: %s",
            uri,
            exc,
        )
        return None  # Fail-open on network errors

    # Decode JWT payload without signature verification
    try:
        parts = jwt_text.split(".")
        if len(parts) < 2:
            raise ValueError("Not a valid JWT (expected at least two '.' separators)")
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        jwt_payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as exc:
        LOGGER.warning("Failed to decode status list JWT from %r: %s", uri, exc)
        return None

    sl = jwt_payload.get("status_list")
    if not isinstance(sl, dict):
        LOGGER.warning("JWT from %r has no 'status_list' claim", uri)
        return None

    bits: int = int(sl.get("bits", 1))
    lst: str = sl.get("lst", "")

    # Decode: base64url (no padding) → zlib decompress → little-endian bitstring bytes
    try:
        compressed = base64.urlsafe_b64decode(lst + "=" * (-len(lst) % 4))
        raw_bytes = zlib.decompress(compressed)
    except Exception as exc:
        LOGGER.warning("Failed to decode status list bitstring from %r: %s", uri, exc)
        return None

    # Extract the status value for credential at position *idx*.
    # IETF Token Status List uses little-endian bit ordering within each byte:
    # bit 0 of the byte is the LSB, so right-shift by the bit position within
    # the byte and mask to *bits* wide.
    bit_pos = int(idx) * bits
    byte_idx = bit_pos // 8
    bit_in_byte = bit_pos % 8

    if byte_idx >= len(raw_bytes):
        LOGGER.warning(
            "Status list index %d is out of range (list byte length=%d); "
            "skipping revocation check",
            idx,
            len(raw_bytes),
        )
        return None

    mask = (1 << bits) - 1
    status_value = (raw_bytes[byte_idx] >> bit_in_byte) & mask

    if status_value != 0:
        return (
            f"Credential is revoked or suspended "
            f"(status_list idx={idx}, status={status_value})"
        )

    return None  # Bit is 0 → credential is valid
