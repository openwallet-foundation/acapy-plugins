"""DID Registration."""

import base64
from typing import Tuple

from aries_askar import Key, KeyAlg

from .crypto import AskarKey


def generate() -> Tuple[str, AskarKey]:
    """Generate a DID."""
    vk = Key.generate(KeyAlg.ED25519)
    jwk = vk.get_jwk_public()
    encoded = base64.urlsafe_b64encode(jwk.encode()).rstrip(b"=").decode()
    did = f"did:jwk:{encoded}"
    key = AskarKey(vk, f"{did}#0")
    return did, key
