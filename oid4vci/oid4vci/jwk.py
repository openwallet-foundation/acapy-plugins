"""did:jwk DID method."""

from aries_cloudagent.wallet.did_method import DIDMethod
from aries_cloudagent.wallet.key_type import ED25519, KeyType


P256: KeyType = KeyType("p256", "p256-pub", b"\x12\x00")

DID_JWK = DIDMethod("jwk", [ED25519, P256])
