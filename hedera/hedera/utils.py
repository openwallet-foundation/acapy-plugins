"""Utility functions that don't fit into a specific module."""

from typing import Type

from acapy_agent.config.injector import InjectType
from acapy_agent.core.profile import ProfileSession
from acapy_agent.wallet.base import BaseWallet
from hiero_did_sdk_python.did.utils import parse_identifier
from hiero_sdk_python import PrivateKey


async def get_encoded_private_key_for_did(wallet: BaseWallet, did: str) -> str:
    """Retrieve the encoded private key string for stored DID."""
    parsed_identifier = parse_identifier(did)
    pubkey_base58 = parsed_identifier.public_key_base58

    pubkey_base58_no_multibase = pubkey_base58[1:]

    key_entry = await wallet._session.handle.fetch_key(name=pubkey_base58_no_multibase)

    if not key_entry:
        raise Exception("Could not fetch key")

    key = key_entry.key

    private_key_bytes = key.get_secret_bytes()

    encoded_private_key = PrivateKey.from_bytes(private_key_bytes).to_string()

    return encoded_private_key


def inject_or_fail(
    session: ProfileSession, base_class: Type[InjectType], exception
) -> InjectType:
    """Inject class from context or immediately fail if not possible."""
    instance = session.inject_or(base_class)

    if not instance:
        raise exception(f"Could not inject class {base_class}")

    return instance
