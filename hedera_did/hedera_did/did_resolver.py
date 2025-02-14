"""Hedera DID resolver."""

import re
from typing import Pattern, cast

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import BaseDIDResolver, ResolverError, ResolverType
from did_sdk_py.did.hedera_did_resolver import HederaDidResolver as SdkHederaDidResolver
from did_sdk_py.did.types import DIDResolutionResult

from .client import get_client_provider
from .config import Config

class HederaDIDResolver(BaseDIDResolver):
    """Hedera DID resolver."""

    def __init__(self):
        """Constructor."""
        super().__init__(ResolverType.NATIVE)
        self._suported_did_regex = re.compile("^did:hedera:.*$")

    @property
    def supported_did_regex(self) -> Pattern:
        """Return list of supported methods."""
        return self._suported_did_regex

    async def setup(self, context):
        """Setup resolver based on current context."""
        settings = Config.from_settings(context.settings)

        network = settings.network
        operator_id = settings.operator_id
        operator_key_der = settings.operator_key_der

        client_provider = get_client_provider(network, operator_id, operator_key_der)

        self._hedera_did_resolver = SdkHederaDidResolver(client_provider)

    async def _resolve(self, profile: Profile, did: str, service_accept = None) -> dict:
        """Resolve Hedera DID."""
        result: DIDResolutionResult = await self._hedera_did_resolver.resolve(did)

        did_resolution_metadata = result.get("didResolutionMetadata")

        if not did_resolution_metadata:
            raise ResolverError("Unknown error")

        if "error" in did_resolution_metadata:
            error_message = did_resolution_metadata.get("message")

            if not error_message:
                raise ResolverError("Unknown error")

            raise ResolverError(error_message)

        return cast(dict, result)
