from typing import List, Dict, Union
from enum import Enum
from base64 import urlsafe_b64encode, b64decode
from hashlib import sha256
import uuid
from multiformats import multibase


class CheqdNetwork(Enum):
    Testnet = "testnet"
    Mainnet = "mainnet"


class MethodSpecificIdAlgo(Enum):
    Base58 = "base58"
    Uuid = "uuid"


class VerificationMethods(Enum):
    Ed255192020 = "Ed25519VerificationKey2020"
    Ed255192018 = "Ed25519VerificationKey2018"
    JWK = "JsonWebKey2020"


class TVerificationKeyPrefix(Enum):
    Placeholder = "prefix"


class CheqdAnoncredsResourceType(Enum):
    schema = "anonCredsSchema"
    credentialDefinition = "anonCredsCredDef"
    revocationRegistryDefinition = "anonCredsRevocRegDef"
    revocationStatusList = "anonCredsStatusList"


TVerificationKey = str
IVerificationKeys = Dict[str, Union[str, TVerificationKey]]
VerificationMethod = Dict[str, Union[str, Dict[str, str]]]
DIDDocument = Dict[str, Union[str, List[str], List[VerificationMethod]]]


def base64_to_bytes(data: str) -> bytes:
    return b64decode(data)


def bytes_to_base64(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("utf-8")


def create_verification_keys(
    public_key_b64: str,
    network: CheqdNetwork = CheqdNetwork.Testnet,
    algo: MethodSpecificIdAlgo = MethodSpecificIdAlgo.Uuid,
    key: TVerificationKey = "key-1",
) -> IVerificationKeys:
    if algo == MethodSpecificIdAlgo.Base58:
        method_specific_id = multibase.encode(
            "base58btc", base64_to_bytes(public_key_b64)
        ).decode()
        did_url = f"did:cheqd:{network.value}:{multibase.encode('base58btc', sha256(base64_to_bytes(public_key_b64)).digest()[:16]).decode()[1:]}"
        return {
            "methodSpecificId": method_specific_id,
            "didUrl": did_url,
            "keyId": f"{did_url}#{key}",
            "publicKey": public_key_b64,
        }
    elif algo == MethodSpecificIdAlgo.Uuid:
        method_specific_id = multibase.encode(
            "base58btc", base64_to_bytes(public_key_b64)
        ).decode()
        did_url = f"did:cheqd:{network.value}:{uuid.uuid4()}"
        return {
            "methodSpecificId": method_specific_id,
            "didUrl": did_url,
            "keyId": f"{did_url}#{key}",
            "publicKey": public_key_b64,
        }


def create_did_verification_method(
    verification_method_types: List[VerificationMethods],
    verification_keys: List[IVerificationKeys],
) -> List[VerificationMethod]:
    methods = []
    for idx, type_ in enumerate(verification_method_types):
        key = verification_keys[idx]
        if type_ == VerificationMethods.Ed255192020:
            methods.append(
                {
                    "id": key["keyId"],
                    "type": type_.value,
                    "controller": key["didUrl"],
                    "publicKeyMultibase": multibase.encode(
                        "base58btc", base64_to_bytes(key["publicKey"])
                    ).decode(),
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
                        "x": bytes_to_base64(base64_to_bytes(key["publicKey"])),
                    },
                }
            )
    return methods


def create_did_payload(
    verification_methods: List[VerificationMethod],
    verification_keys: List[IVerificationKeys],
) -> DIDDocument:
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
