"""Utilities for shared functions."""

import base64
import hashlib
import json

import jcs
from multiformats import multibase, multihash

from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.keys.manager import MultikeyManager

WITNESS_CONNECTION_ALIAS_SUFFIX = "@witness"
ALIAS_PURPOSES = {
    "witnessConnection": "@witness",
    "nextKey": "@nextKey",
    "updateKey": "@updateKey",
    "witnessKey": "@witnessKey",
}


def url_to_domain(url: str):
    """Get server domain."""
    domain = url.split("://")[-1]
    if "%3A" in domain:
        domain = domain.replace("%3A", ":")
    return domain


def create_alias(identifier: str, purpose: str):
    """Get static alias."""
    return f"webvh:{identifier}{ALIAS_PURPOSES[purpose]}"


def decode_invitation(invitation_url: str):
    """Decode an oob invitation url."""
    encoded_invitation = invitation_url.split("oob=")[-1]
    return json.loads(base64.urlsafe_b64decode(f"{encoded_invitation}===").decode())


def key_hash(key):
    """Return key hash."""
    return multibase.encode(multihash.digest(key.encode(), "sha2-256"), "base58btc")[1:]


def multikey_to_jwk(multikey):
    """Derive JWK."""
    # TODO, support other key types than ed25519
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(multibase.decode(multikey)[2:])
        .decode()
        .rstrip("="),
    }
    thumbprint = (
        base64.urlsafe_b64encode(hashlib.sha256(jcs.canonicalize(jwk)).digest())
        .decode()
        .rstrip("=")
    )
    return jwk, thumbprint


def all_are_not_none(*args):
    """Check if all arguments are not None."""
    return all(v is not None for v in args)


def get_namespace_and_identifier_from_did(did: str):
    """Extract namespace and identifier from a DID."""
    parts = did.split(":")
    if len(parts) < 5:
        raise ValueError(
            "Invalid DID format. Expected 'did:webvh:<url>:<namespace>:<identifier>'"
        )

    return parts[4], parts[5]


async def create_key(profile, kid=None) -> str:
    """Create key shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).create(alg="ed25519", kid=kid)
    return key.get("multikey")


async def find_key(profile, kid) -> str | None:
    """Find key given a key id shortcut."""
    try:
        async with profile.session() as session:
            key = await MultikeyManager(session).from_kid(
                kid=kid,
            )
        return key.get("multikey")
    except AttributeError:
        return None


async def find_multikey(profile, multikey) -> str:
    """Find multikey shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).from_multikey(multikey)
    return key.get("multikey")


async def bind_key(profile, multikey, kid) -> str:
    """Bind key to a given key id shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).update(
            kid=kid,
            multikey=multikey,
        )
    return key.get("multikey")


async def unbind_key(profile, multikey, kid):
    """Unbind key id from key shortcut."""
    async with profile.session() as session:
        await MultikeyManager(session).unbind_key_id(
            kid=kid,
            multikey=multikey,
        )


async def add_proof(profile, document, verification_method) -> dict:
    """Add data integrity proof to document shortcut."""
    async with profile.session() as session:
        signed_document = await DataIntegrityManager(session).add_proof(
            document,
            DataIntegrityProofOptions(
                type="DataIntegrityProof",
                cryptosuite="eddsa-jcs-2022",
                proof_purpose="assertionMethod",
                verification_method=verification_method,
            ),
        )
    return signed_document


async def verify_proof(profile, document) -> bool:
    """Verify data integrity proof shortcut."""
    async with profile.session() as session:
        verified = await DataIntegrityManager(session).verify_proof(document)
    return verified


def validate_did(did: str, domain: str, namespace: str, identifier: str) -> bool:
    """Validate a did aginst the components."""
    return (
        True
        if (
            did.split(":")[3] == domain
            and did.split(":")[4] == namespace
            and did.split(":")[5] == identifier
        )
        else False
    )
