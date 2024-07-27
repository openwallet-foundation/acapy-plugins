"""did:jwk DID method."""

from aries_cloudagent.wallet.did_method import DIDMethod
from aries_cloudagent.wallet.key_type import ED25519

DID_JWK = DIDMethod("jwk", [ED25519])
