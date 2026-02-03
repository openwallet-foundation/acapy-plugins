"""did:indy support."""

import logging
from typing import Optional

from acapy_agent.core.error import BaseError
from acapy_agent.core.profile import ProfileSession
from acapy_agent.wallet.base import BaseWallet

from did_indy.author.author import AuthorDependencies
from did_indy.driver.ledgers import Ledgers
from did_indy.ledger import LedgerPool, TaaAcceptance
from did_indy.signer import Signer

from .taa_storage import get_taa_acceptance

LOGGER = logging.getLogger(__name__)
CACHE_TTL = 3600


class IndyRegistryError(BaseError):
    """Raised on errors in registrar."""


class AcapyAuthorDeps(AuthorDependencies):
    """Fulfill Author interface dependencies with ACA-Py fixtures."""

    def __init__(self, session: ProfileSession):
        """Init deps."""
        self.session = session

    async def get_signer(self, did: str) -> Signer:
        """Retreive a signer for a did.

        The signer is the verkey associated with the DID which will always be:
            {did}#verkey
        because of how we store the key in the wallet on creation.
        """
        wallet = self.session.inject(BaseWallet)
        signer = await wallet.get_key_by_kid(did + "#verkey")

        async def _signer(message: bytes) -> bytes:
            return await wallet.sign_message(message, from_verkey=signer.verkey)

        return _signer

    async def get_pool(self, namespace: str) -> LedgerPool:
        """Get the ledger pool for a namespace."""
        ledgers = self.session.inject(Ledgers)
        pool = ledgers.get(namespace)
        if not pool or not isinstance(pool, LedgerPool):
            raise Exception("Invalid pool for namespace " + namespace)
        return pool

    async def get_taa(self, namespace: str) -> Optional[TaaAcceptance]:
        """Get a Transaction Author Agreement from storage.

        Args:
            namespace: The namespace to retrieve TAA for.

        Returns:
            The TAA acceptance record if found, None otherwise
        """
        ledgers = self.session.inject(Ledgers)
        pool = ledgers.get(namespace)

        wallet_id = self.session.settings.get("wallet_id")
        cache_key = f"{namespace}_taa_cache::{wallet_id}"

        # Check cache
        cached_taa_acceptance = await pool.cache.get(cache_key)
        if cached_taa_acceptance is not None:
            LOGGER.debug(
                f"Retrieved cached TAA for namespace {namespace}: {cached_taa_acceptance}"
            )
            return cached_taa_acceptance

        # Retrieve the TAA from storage
        taa_record = await get_taa_acceptance(self.session, namespace)
        LOGGER.debug(f"Retrieved TAA for namespace {namespace}: {taa_record}")

        taa_acceptance = (
            TaaAcceptance(
                taaDigest=taa_record.digest,
                mechanism=taa_record.mechanism,
                time=taa_record.accepted_at,
            )
            if taa_record
            else None
        )

        if taa_acceptance is not None:
            await pool.cache.set(cache_key, taa_acceptance, ttl=CACHE_TTL)
            
        return taa_acceptance
