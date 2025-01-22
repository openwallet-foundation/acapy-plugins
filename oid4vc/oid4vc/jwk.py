"""did:jwk DID method."""

from acapy_agent.wallet.did_method import DIDMethod
from acapy_agent.wallet.key_type import ED25519, KeyType

P256: KeyType = KeyType("p256", "p256-pub", b"\x12\x00", jws_alg=None)

DID_JWK = DIDMethod("jwk", [ED25519, P256])
