"""DID Registration."""

import json
from typing import Tuple

from aries_askar import Key, KeyAlg
from did_peer_4 import encode

from .crypto import AskarKey


def generate() -> Tuple[str, AskarKey]:
    """Generate a DID."""
    vk = Key.generate(KeyAlg.ED25519)
    input_doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [
            {
                "id": "#auth",
                "type": "Ed25519VerificationKey2020",
                "publicKeyJwk": json.loads(vk.get_jwk_public()),
            }
        ],
        "authentication": ["#auth"],
    }
    did = encode(input_doc)
    key = AskarKey(vk, f"{did}#auth")
    return did, key
