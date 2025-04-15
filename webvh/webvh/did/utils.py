"""Utilities for shared functions."""

import base64
import jcs
import json
import hashlib
from multiformats import multibase, multihash

from aiohttp import ClientResponseError, ClientSession

from did_webvh.core.state import DocumentState

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


async def fetch_jsonl(url):
    """Fetch a JSONL file from the given URL."""
    async with ClientSession() as session:
        async with session.get(url) as response:
            # Check if the response is OK
            response.raise_for_status()

            # Read the response line by line
            async for line in response.content:
                # Decode each line and parse as JSON
                decoded_line = line.decode("utf-8").strip()
                if decoded_line:  # Ignore empty lines
                    yield json.loads(decoded_line)


async def fetch_document_state(url):
    """Fetch a JSONL file from the given URL."""
    # Get the document state from the server
    document_state = None
    try:
        async for line in fetch_jsonl(url):
            document_state = DocumentState.load_history_line(line, document_state)
    except ClientResponseError:
        pass
    return document_state
