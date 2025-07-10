"""Constant values."""

ALIASES = {
    "witnessConnection": "@witness",
    "nextKey": "@nextKey",
    "updateKey": "@updateKey",
    "witnessKey": "@witnessKey",
}

PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
}

SUPPORTED_KEY_TYPES = ["Multikey", "JsonWebKey"]

WEBVH_METHOD = "did:webvh:1.0"
