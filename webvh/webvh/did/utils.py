"""Utilities for shared functions."""

from acapy_agent.wallet.error import WalletDuplicateError
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


def create_alias(identifier: str, purpose: str):
    """Get static alias."""
    return f"webvh:{identifier}{ALIAS_PURPOSES[purpose]}"


def key_to_did_key_vm(multikey: str):
    """Transform a multikey to a did key verification method."""
    return f"did:key:{multikey}#{multikey}"


def server_url_to_domain(server_url: str):
    """Replace %3A with : if domain is URL encoded."""
    domain = server_url.split("://")[-1]
    # if "%3A" in domain:
    #     domain = domain.replace("%3A", ":")
    return domain


def get_url_decoded_domain(domain: str):
    """Replace %3A with : if domain is URL encoded."""
    if "%3A" in domain:
        return domain.replace("%3A", ":")
    return domain


async def create_or_get_key(profile, key_alias, key=None):
    """Create new multikey with alias or return existing one."""
    async with profile.session() as session:
        try:
            if key:
                key_info = await MultikeyManager(session).update(
                    kid=key_alias,
                    multikey=key,
                )

            else:
                key_info = await MultikeyManager(session).create(
                    kid=key_alias,
                    alg="ed25519",
                )
        except (MultikeyManagerError, WalletDuplicateError):
            key_info = await MultikeyManager(session).from_kid(key_alias)
    return key_info


async def sign_document(session, document, proof_options):
    """Sign document with data integrity proof."""
    return await DataIntegrityManager(session).add_proof(
        document, DataIntegrityProofOptions.deserialize(proof_options)
    )
