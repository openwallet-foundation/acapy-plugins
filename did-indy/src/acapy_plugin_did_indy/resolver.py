"""did:indy resolver."""

import logging
import re
from typing import Optional, Pattern, Sequence, Text
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.valid import B58
from acapy_agent.resolver.base import (
    BaseDIDResolver,
    DIDNotFound,
    ResolverError,
    ResolverType,
)
from indy_vdr import Resolver, VdrError, VdrErrorCode, open_pool

from did_indy.driver.ledgers import Ledgers

LOGGER = logging.getLogger(__name__)

INDY_DID_PATTERN = re.compile(
    rf"^did:indy:(?P<namespace>[^:]+(:[^:]+)?):[{B58}]{{21,22}}$"
)


class IndyResolver(BaseDIDResolver):
    """Indy DID Resolver."""

    SERVICE_TYPE_DID_COMMUNICATION = "did-communication"
    SERVICE_TYPE_DIDCOMM = "DIDComm"
    SERVICE_TYPE_ENDPOINT = "endpoint"
    CONTEXT_DIDCOMM_V2 = "https://didcomm.org/messaging/contexts/v2"

    def __init__(self):
        """Initialize Indy Resolver."""
        super().__init__(ResolverType.NATIVE)
        self._resolver: Resolver | None = None

    async def setup(self, context: InjectionContext):
        """Perform required setup for Indy DID resolution."""
        settings = context.settings.for_plugin("acapy_did_indy")
        auto = settings.get_bool("auto_ledger")
        ledgers = context.inject(Ledgers)
        if auto:
            resolver = Resolver(autopilot=True)
        elif ledgers:
            resolver = Resolver(
                pool_map={
                    name: await open_pool(transactions=ledger_pool.genesis_txns)
                    for name, ledger_pool in ledgers.ledgers.items()
                }
            )
        else:
            raise ResolverError(
                "Could not configure indy resolver; missing auto flag or ledger map"
            )

        self._resolver = resolver

    @property
    def resolver(self):
        """Return resolver."""
        LOGGER.info("DID:Indy resolver: %s", self._resolver)
        assert self._resolver, "Setup should be called before using resolver"
        return self._resolver

    @property
    def supported_did_regex(self) -> Pattern:
        """Return supported_did_regex of Indy DID Resolver."""
        LOGGER.info("DID:Indy resolver supported_did_regex: %s", INDY_DID_PATTERN)
        return INDY_DID_PATTERN

    async def _resolve(
        self,
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve an indy DID."""
        LOGGER.info("DID:Indy Resolving DID: %s", did)
        try:
            resolve_result = await self.resolver.resolve(did)
        except VdrError as error:
            if error.code == VdrErrorCode.RESOLVER and "Object not found" in str(error):
                raise DIDNotFound(f"DID {did} not found") from error
            raise ResolverError("Unexpected error in Indy resolver") from error

        doc = resolve_result["didDocument"]
        return doc
