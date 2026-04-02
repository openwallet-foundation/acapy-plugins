"""mso_mdoc item value extraction and presentation input normalization helpers."""

import base64
import json
import logging
from typing import Any

from oid4vc.cred_processor import PresVerifierError

LOGGER = logging.getLogger(__name__)


def extract_mdoc_item_value(item: Any) -> Any:
    """Extract the actual value from an MDocItem enum variant.

    MDocItem is a Rust enum exposed via UniFFI with variants:
    - TEXT(str)
    - BOOL(bool)
    - INTEGER(int)
    - ARRAY(List[MDocItem])
    - ITEM_MAP(Dict[str, MDocItem])

    Each variant stores its value in _values[0].
    """
    if item is None:
        return None

    # Check if it's an MDocItem variant by checking for _values attribute
    if hasattr(item, "_values") and item._values:
        inner_value = item._values[0]

        # Handle nested structures recursively
        if isinstance(inner_value, dict):
            return {k: extract_mdoc_item_value(v) for k, v in inner_value.items()}
        elif isinstance(inner_value, list):
            return [extract_mdoc_item_value(v) for v in inner_value]
        else:
            return inner_value

    # Already a plain value
    return item


def extract_verified_claims(verified_response: dict) -> dict:
    """Extract claims from MdlReaderVerifiedData.verified_response.

    The verified_response is structured as:
    dict[str, dict[str, MDocItem]]
    e.g. {"org.iso.18013.5.1": {"given_name": MDocItem.TEXT("Alice"), ...}}

    This function converts it to:
    {"org.iso.18013.5.1": {"given_name": "Alice", ...}}
    """
    claims = {}
    for namespace, elements in verified_response.items():
        ns_claims = {}
        for element_name, mdoc_item in elements.items():
            ns_claims[element_name] = extract_mdoc_item_value(mdoc_item)
        claims[namespace] = ns_claims
    return claims


def _normalize_presentation_input(presentation: Any) -> tuple[list, bool]:
    """Normalize presentation input to a list.

    Args:
        presentation: The presentation data

    Returns:
        Tuple of (list of presentations, is_list_input flag)
    """
    if isinstance(presentation, str):
        try:
            parsed = json.loads(presentation)
            if isinstance(parsed, list):
                return parsed, True
        except json.JSONDecodeError:
            pass
        return [presentation], False
    elif isinstance(presentation, list):
        return presentation, True
    return [presentation], False


def _decode_presentation_bytes(pres_item: Any) -> bytes:
    """Decode presentation item to bytes.

    Args:
        pres_item: The presentation item (string or bytes)

    Returns:
        Decoded bytes

    Raises:
        PresVerifierError: If unable to decode to bytes
    """
    if isinstance(pres_item, bytes):
        return pres_item

    if isinstance(pres_item, str):
        # Try base64url decode
        try:
            return base64.urlsafe_b64decode(pres_item + "=" * (-len(pres_item) % 4))
        except (ValueError, TypeError):
            pass
        # Try hex decode
        try:
            return bytes.fromhex(pres_item)
        except (ValueError, TypeError):
            pass

    raise PresVerifierError("Presentation must be bytes or base64/hex string")
