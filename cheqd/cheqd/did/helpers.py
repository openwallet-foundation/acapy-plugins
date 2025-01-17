"""Helpers for did:cheqd."""

from enum import Enum
from hashlib import sha256
from typing import Dict, List, Union
from uuid import uuid4

from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b58, bytes_to_b64
from acapy_agent.utils.multiformats import multibase, multicodec


class CheqdNetwork(Enum):
    """Network types in cheqd."""

    Testnet = "testnet"
    Mainnet = "mainnet"


class MethodSpecificIdAlgo(Enum):
    """Method specific Identifies type."""

    Base58 = "base58"
    Uuid = "uuid"


class VerificationMethods(Enum):
    """Verification Method Type."""

    Ed255192020 = "Ed25519VerificationKey2020"
    Ed255192018 = "Ed25519VerificationKey2018"
    JWK = "JsonWebKey2020"


class CheqdAnoncredsResourceType(Enum):
    """Resource type values for anoncreds objects."""

    schema = "anonCredsSchema"
    credentialDefinition = "anonCredsCredDef"
    revocationRegistryDefinition = "anonCredsRevocRegDef"
    revocationStatusList = "anonCredsStatusList"


TVerificationKey = str
IVerificationKeys = Dict[str, Union[str, TVerificationKey]]
VerificationMethod = Dict[str, Union[str, Dict[str, str]]]
DIDDocument = Dict[str, Union[str, List[str], List[VerificationMethod]]]


def create_verification_keys(
    public_key_b64: str,
    network: CheqdNetwork = CheqdNetwork.Testnet,
    algo: MethodSpecificIdAlgo = MethodSpecificIdAlgo.Uuid,
    key: TVerificationKey = "key-1",
) -> IVerificationKeys:
    """Construct a verification key from a public key."""
    if algo == MethodSpecificIdAlgo.Base58:
        method_specific_id = bytes_to_b58(b64_to_bytes(public_key_b64))
        did_url = f"did:cheqd:{network.value}:{
            multibase.encode(
                sha256(b64_to_bytes(public_key_b64)).digest()[:16], 'base58btc'
            )[1:]
        }"

        return {
            "methodSpecificId": method_specific_id,
            "didUrl": did_url,
            "keyId": f"{did_url}#{key}",
            "publicKey": public_key_b64,
        }
    elif algo == MethodSpecificIdAlgo.Uuid:
        method_specific_id = uuid4()
        did_url = f"did:cheqd:{network}:{method_specific_id}"
        return {
            "methodSpecificId": method_specific_id,
            "didUrl": did_url,
            "keyId": f"{did_url}#{key}",
            "publicKey": public_key_b64,
        }


MULTICODEC_ED25519_HEADER = bytes([0xED, 0x01])


def to_multibase_raw(key: bytes) -> str:
    """Converts a raw key to multibase with the MULTICODEC_ED25519_HEADER.

    Args:
        key (bytes): The raw key as bytes.

    Returns:
        str: Multibase-encoded key as a Base58btc string.
    """
    # Concatenate the header and the key
    multibase_data = multicodec.wrap("ed25519-pub", key)

    # Encode to Base58btc multibase
    multibase_encoded = multibase.encode(multibase_data, "base58btc")

    return multibase_encoded


def create_did_verification_method(
    verification_method_types: List[VerificationMethods],
    verification_keys: List[IVerificationKeys],
) -> List[VerificationMethod]:
    """Construct Verification Method."""
    methods = []
    for idx, type_ in enumerate(verification_method_types):
        key = verification_keys[idx]
        if type_ == VerificationMethods.Ed255192020:
            methods.append(
                {
                    "id": key["keyId"],
                    "type": type_.value,
                    "controller": key["didUrl"],
                    "publicKeyMultibase": to_multibase_raw(
                        b64_to_bytes(key["publicKey"])
                    ),
                }
            )
        elif type_ == VerificationMethods.Ed255192018:
            methods.append(
                {
                    "id": key["keyId"],
                    "type": type_.value,
                    "controller": key["didUrl"],
                    "publicKeyBase58": key["methodSpecificId"][1:],
                }
            )
        elif type_ == VerificationMethods.JWK:
            methods.append(
                {
                    "id": key["keyId"],
                    "type": type_.value,
                    "controller": key["didUrl"],
                    "publicKeyJwk": {
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": bytes_to_b64(b64_to_bytes(key["publicKey"])),
                    },
                }
            )
    return methods


def create_did_payload(
    verification_methods: List[VerificationMethod],
    verification_keys: List[IVerificationKeys],
) -> DIDDocument:
    """Construct DID Document."""
    if not verification_methods:
        raise ValueError("No verification methods provided")
    if not verification_keys:
        raise ValueError("No verification keys provided")

    did = verification_keys[0]["didUrl"]
    return {
        "id": did,
        "controller": [key["didUrl"] for key in verification_keys],
        "verificationMethod": verification_methods,
        "authentication": [key["keyId"] for key in verification_keys],
    }
