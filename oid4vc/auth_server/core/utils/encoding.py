"""Base64url (no-pad) encode/decode."""

import base64


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64url_decode(data: str) -> bytes:
    """Reverse of b64url_encode, tolerates missing padding."""
    return base64.urlsafe_b64decode(data + "===")
