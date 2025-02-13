"""Hedera DID registrar."""

from acapy_agent.wallet.base import BaseWallet, DIDInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from hiero_did_sdk_python.did.hedera_did_resolver import HederaDid
from hiero_sdk_python import PrivateKey

from ..client import get_client
from ..config import Config
from .did_method import HEDERA


class HederaDIDRegistrar:
    """Hedera DID registrar."""

    def __init__(self, context):
        """Constructor."""
        self.context = context

        config = Config.from_settings(context.settings)

        network = config.network
        operator_id = config.operator_id
        operator_key = config.operator_key

        self._client = get_client(network, operator_id, operator_key)

    async def register(self, key_type, seed=None) -> DIDInfo:
        """Register Hedera DID."""
        async with self.context.session() as session:
            key_types = session.inject_or(KeyTypes)

            if not key_types:
                raise Exception("Failed to inject supported key types enum")

            key_type = key_types.from_key_type(key_type) or ED25519

            wallet = session.inject_or(BaseWallet)

            if not wallet:
                raise Exception("Failed to inject wallet instance")

            key_info = await wallet.create_key(ED25519, seed=seed)

            key_entry = await wallet._session.handle.fetch_key(name=key_info.verkey)

            if not key_entry:
                raise Exception("Could not fetch key")

            private_key_bytes = key_entry.key.get_secret_bytes()

            hedera_did = HederaDid(
                self._client,
                private_key_der=PrivateKey.from_bytes(private_key_bytes).to_string(),
            )

            await hedera_did.register()

            did = hedera_did.identifier

            info: DIDInfo = {
                "did": did,
                "verkey": key_info.verkey,
                "key_type": key_type.key_type,
            }

            await wallet._session.handle.insert(
                "did",
                did,
                value_json={
                    "did": did,
                    "method": HEDERA.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": {},
                },
                tags={
                    "method": HEDERA.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                },
            )

            return info
