"""DID Registration."""

import base64
import json
from typing import Literal, Tuple

from aries_askar import Key, KeyAlg

from .crypto import AskarKey


def generate(key_type: Literal["ed25519", "secp256k1"]) -> Tuple[str, AskarKey]:
    """Generate a DID."""
    if key_type == "ed25519":
        vk = Key.generate(KeyAlg.ED25519)
    elif key_type == "secp256k1":
        vk = Key.generate(KeyAlg.K256)
    else:
        raise ValueError(f"Unknown key type: {key_type}")

    jwk = json.loads(vk.get_jwk_public())
    jwk["use"] = "sig"
    encoded = base64.urlsafe_b64encode(json.dumps(jwk).encode()).rstrip(b"=").decode()
    did = f"did:jwk:{encoded}"
    key = AskarKey(vk, f"{did}#0")
    return did, key
