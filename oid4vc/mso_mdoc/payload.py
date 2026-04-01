"""Payload preparation and result normalisation for mso_mdoc credential issuance.

Provides two module-level helpers consumed by ``MsoMdocCredProcessor.issue``:

- ``prepare_mdoc_payload`` — flattens a namespaced credential-subject dict into
  the flat structure expected by isomdl and base64-encodes binary fields such
  as ``portrait``.
- ``normalize_mdoc_result`` — converts the raw return value of
  ``isomdl_mdoc_sign`` (which may be bytes, a ``b'...'`` string, or a plain
  string) into a consistent plain string for storage and transmission.
"""

import base64
import logging
from typing import Any, Dict, Optional

from oid4vc.cred_processor import CredProcessorError

LOGGER = logging.getLogger(__name__)


def prepare_mdoc_payload(
    payload: Dict[str, Any], doctype: Optional[str] = None
) -> Dict[str, Any]:
    """Prepare a credential-subject payload for mDoc issuance.

    Performs two transformations:

    1. **Doctype flattening** — if the payload contains a top-level key equal
       to ``doctype`` whose value is a dict (namespace-wrapped claims), those
       claims are merged into the top-level dict.  A warning is emitted when
       any existing top-level key would be overwritten.

    2. **Portrait encoding** — if a ``portrait`` field is present as
       ``bytes`` or a list of integers, it is base64-encoded to a string as
       required by the isomdl-uniffi Rust library.

    Args:
        payload: Raw credential-subject dictionary from the exchange record.
        doctype: Document type string (e.g. ``"org.iso.18013.5.1.mDL"``).
            When provided and present as a key in ``payload``, the nested
            dict under that key is flattened into the top level.

    Returns:
        Transformed payload dict ready to pass to ``isomdl_mdoc_sign``.
    """
    prepared = payload.copy()

    if doctype and doctype in prepared:
        doctype_claims = prepared.pop(doctype)
        if isinstance(doctype_claims, dict):
            conflicts = set(doctype_claims.keys()) & set(prepared.keys())
            if conflicts:
                LOGGER.warning(
                    "Payload namespace flattening for doctype '%s': "
                    "top-level keys %s will be overwritten by doctype claims",
                    doctype,
                    sorted(conflicts),
                )
            LOGGER.debug(
                "Flattening doctype wrapper '%s' (%d claims) into top-level payload",
                doctype,
                len(doctype_claims),
            )
            prepared.update(doctype_claims)

    if "portrait" in prepared:
        portrait = prepared["portrait"]
        if isinstance(portrait, bytes):
            prepared["portrait"] = base64.b64encode(portrait).decode("utf-8")
        elif isinstance(portrait, list):
            try:
                prepared["portrait"] = base64.b64encode(bytes(portrait)).decode("utf-8")
            except Exception:
                pass  # leave as-is; isomdl will surface the error

    return prepared


def normalize_mdoc_result(result: Any) -> str:
    """Normalise the raw return value of ``isomdl_mdoc_sign`` to a plain string.

    The isomdl-uniffi Rust library may return bytes, a ``b'...'``-style string
    literal, or a plain string depending on the binding version.  This function
    normalises all three forms so callers always receive a consistent string.

    Args:
        result: Raw value returned by ``isomdl_mdoc_sign``.

    Returns:
        Normalised string representation of the signed mDoc credential.

    Raises:
        CredProcessorError: If ``result`` is ``None`` or cannot be converted.
    """
    if result is None:
        raise CredProcessorError(
            "mDoc signing returned None result. Check key material and payload format."
        )

    if isinstance(result, bytes):
        try:
            return result.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CredProcessorError(
                f"Failed to decode mDoc bytes result: {e}. "
                "Result may contain binary data requiring base64 encoding."
            ) from e

    if isinstance(result, str):
        if result.startswith("b'") and result.endswith("'"):
            # Strip the b'...' wrapper.  Do NOT use codecs.decode with
            # "unicode_escape" — that interprets escape sequences in
            # attacker-controlled input and can be exploited for code-path
            # attacks.  The hex/base64 output of isomdl-uniffi is plain ASCII.
            return result[2:-1]
        if result.startswith('b"') and result.endswith('"'):
            return result[2:-1]
        return result

    try:
        return str(result)
    except Exception as e:
        raise CredProcessorError(
            f"Failed to normalize mDoc result of type {type(result).__name__}: {e}"
        ) from e
