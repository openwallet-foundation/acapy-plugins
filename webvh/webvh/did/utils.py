"""Utilities for shared functions."""

import base64
import jcs
import json
import hashlib
from datetime import datetime, timezone
from multiformats import multibase, multihash

from aiohttp import ClientResponseError, ClientSession

from did_webvh.resolver import ResolutionResult, resolve_did
from did_webvh.core.state import DocumentState

from acapy_agent.wallet.error import WalletDuplicateError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.did_method import KEY
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    MultikeyManagerError,
)
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions

WITNESS_CONNECTION_ALIAS_SUFFIX = "@witness"

KEY_ID_SUFFIXES = {"next": "#next", "update": "#update", "witness": "#witness"}
ALIAS_PURPOSES = {
    "witnessConnection": "@witness",
    "nextKey": "@nextKey",
    "updateKey": "@updateKey",
    "witnessKey": "@witnessKey",
}


def version_time():
    """Create versionTime timestamp for log entries."""
    return str(datetime.now(timezone.utc).isoformat("T", "seconds")).replace(
        "+00:00", "Z"
    )


def log_entry_hash(log_entry):
    """Create hash for log entries."""
    return multibase.encode(
        multihash.digest(jcs.canonicalize(log_entry), "sha2-256"), "base58btc"
    )[1:]


def create_alias(identifier: str, purpose: str):
    """Get static alias."""
    return f"webvh:{identifier}{ALIAS_PURPOSES[purpose]}"


def key_to_did_key_vm(multikey: str):
    """Transform a multikey to a did key verification method."""
    return f"did:key:{multikey}#{multikey}"


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


async def create_or_get_witness_did(profile, key_alias, key=None):
    """Create new multikey with alias or return existing one."""
    async with profile.session() as session:
        manager = MultikeyManager(session)
        try:
            if key:
                key_info = await manager.update(
                    kid=key_alias,
                    multikey=key,
                )

            else:
                wallet = session.inject_or(BaseWallet)
                info = await wallet.create_local_did(method=KEY, key_type=ED25519)
                key_info = await manager.update(
                    kid=key_alias,
                    multikey=info.did.split(":")[-1],
                )
                # key_info = await manager.create(
                #     kid=key_alias,
                #     alg="ed25519",
                # )
        except (MultikeyManagerError, WalletDuplicateError):
            key_info = await manager.from_kid(key_alias)
    return key_info


async def create_or_get_key(profile, key_alias, key=None):
    """Create new multikey with alias or return existing one."""
    async with profile.session() as session:
        manager = MultikeyManager(session)
        try:
            if key:
                key_info = await manager.update(
                    kid=key_alias,
                    multikey=key,
                )

            else:
                key_info = await manager.create(
                    kid=key_alias,
                    alg="ed25519",
                )
        except (MultikeyManagerError, WalletDuplicateError):
            key_info = await manager.from_kid(key_alias)
    return key_info


async def sign_document(session, document, proof_options):
    """Sign document with data integrity proof."""
    return await DataIntegrityManager(session).add_proof(
        document, DataIntegrityProofOptions.deserialize(proof_options)
    )


def decode_invitation(invitation_url: str):
    """Decode an oob invitation url."""
    encoded_invitation = invitation_url.split("oob=")[-1]
    return json.loads(base64.urlsafe_b64decode(f"{encoded_invitation}===").decode())


def key_hash(key):
    """Return key hash."""
    return multibase.encode(multihash.digest(key.encode(), "sha2-256"), "base58btc")[1:]


async def create_signing_key(profile, did: str, key_id: str = None, key_type=None):
    """Create new signing key."""
    async with profile.session() as session:
        manager = MultikeyManager(session)
        signing_key_info = await manager.create(alg="ed25519")
        signing_key = signing_key_info.get("multikey")
        await manager.update(kid=f"{did}#{signing_key}", multikey=signing_key)
    return signing_key


async def update_signing_key(profile, key, kid):
    """Update signing key."""
    async with profile.session() as session:
        await MultikeyManager(session).update(
            kid=kid,
            multikey=key,
        )


async def delete_signing_key(profile, key_id):
    """Delete signing key."""
    async with profile.session() as session:
        key_info = await MultikeyManager(session).from_kid(
            kid=key_id,
        )
        await MultikeyManager(session).update(
            kid="",
            multikey=key_info.get("multikey"),
        )


async def resolve(did):
    """Resolve did."""
    response = await resolve_did(did)
    if response.resolution_metadata and response.resolution_metadata.get("error"):
        return response.resolution_metadata
    return response


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


async def rotate_keys(profile, did, next_key_hash):
    """Rotate prerotation keys."""

    update_key_id = f"{did}#updateKey"
    next_key_id = f"{did}#nextKey"

    async with profile.session() as session:
        manager = MultikeyManager(session)

        # Find current keys
        update_key_info = await manager.from_kid(kid=update_key_id)
        next_key_info = await manager.from_kid(kid=next_key_id)

        if key_hash(next_key_info.get("multikey")) != next_key_hash:
            pass

        # Unbind current update key and replace with next key
        await manager.update(kid="", multikey=update_key_info.get("multikey"))
        await manager.update(kid=update_key_id, multikey=next_key_info.get("multikey"))
        update_key_info = next_key_info

        # Create and update the new next key
        next_key_info = await manager.create(alg="ed25519")
        await manager.update(kid=next_key_id, multikey=next_key_info.get("multikey"))

        return update_key_info.get("multikey"), key_hash(next_key_info.get("multikey"))


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
