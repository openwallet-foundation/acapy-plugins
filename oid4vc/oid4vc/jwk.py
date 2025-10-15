"""did:jwk DID method."""

from acapy_agent.wallet.did_method import DIDMethod
from acapy_agent.wallet.key_type import ED25519, P256

DID_JWK = DIDMethod("jwk", [ED25519, P256])
