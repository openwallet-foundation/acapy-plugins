"""Utilities for shared functions."""

import base64
import hashlib
import json

import jcs
from multiformats import multibase, multihash

WITNESS_CONNECTION_ALIAS_SUFFIX = "@witness"
ALIAS_PURPOSES = {
    "witnessConnection": "@witness",
    "nextKey": "@nextKey",
    "updateKey": "@updateKey",
    "witnessKey": "@witnessKey",
}


def create_alias(identifier: str, purpose: str):
    """Get static alias."""
    return f"webvh:{identifier}{ALIAS_PURPOSES[purpose]}"


def server_url_to_domain(server_url: str):
    """Replace %3A with : if domain is URL encoded."""
    domain = server_url.split("://")[-1]
    if "%3A" in domain:
        domain = domain.replace("%3A", ":")
    return domain


def get_url_decoded_domain(domain: str):
    """Replace %3A with : if domain is URL encoded."""
    if "%3A" in domain:
        return domain.replace("%3A", ":")
    return domain


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
