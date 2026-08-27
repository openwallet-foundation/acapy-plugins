import logging
from typing import List, Optional

from acapy_agent.wallet.askar import AskarWallet
from acapy_agent.wallet.did_method import INDY, SOV
from acapy_agent.wallet.error import WalletError

from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError
from ..profile.askar_profile import AskarProfileSession

LOGGER = logging.getLogger(__name__)


class IndyAskarWallet(AskarWallet):
    """Indy-specific Askar Wallet implementation."""

    def __init__(self, session: AskarProfileSession):
        super().__init__(session)
        self._session = session

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        ledger: BaseLedger,
        endpoint_type: Optional[EndpointType] = None,
        write_ledger: bool = True,
        endorser_did: Optional[str] = None,
        routing_keys: Optional[List[str]] = None,
    ):
        """Update the endpoint for a DID in the wallet, send to ledger if posted.

        Args:
            did (str): The DID for which to set the endpoint.
            endpoint (str): The endpoint to set. Use None to clear the endpoint.
            ledger (BaseLedger): The ledger to which to send the endpoint update if the
                DID is public or posted.
            endpoint_type (EndpointType, optional): The type of the endpoint/service.
                Only endpoint_type 'endpoint' affects the local wallet. Defaults to None.
            write_ledger (bool, optional): Whether to write the endpoint update to the
                ledger. Defaults to True.
            endorser_did (str, optional): The DID of the endorser. Defaults to None.
            routing_keys (List[str], optional): The routing keys to be used.
                Defaults to None.

        Raises:
            WalletError: If the DID is not of type 'did:sov'.
            LedgerConfigError: If no ledger is available but the DID is public.

        Returns:
            dict: The attribute definition if write_ledger is False, otherwise None.

        """
        LOGGER.debug("Setting endpoint for DID %s to %s", did, endpoint)
        did_info = await self.get_local_did(did)
        if did_info.method not in (SOV, INDY):
            raise WalletError(
                "Setting DID endpoint is only allowed for did:sov or did:indy DIDs"
            )
        metadata = {**did_info.metadata}
        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT
        if endpoint_type == EndpointType.ENDPOINT:
            metadata[endpoint_type.indy] = endpoint

        wallet_public_didinfo = await self.get_public_did()
        if (
            wallet_public_didinfo and wallet_public_didinfo.did == did
        ) or did_info.metadata.get("posted"):
            # if DID on ledger, set endpoint there first
            if not ledger:
                LOGGER.error("No ledger available but DID %s is public", did)
                raise LedgerConfigError(
                    f"No ledger available but DID {did} is public: missing wallet-type?"
                )
            if not ledger.read_only:
                LOGGER.debug("Updating endpoint for DID %s on ledger", did)
                async with ledger:
                    attrib_def = await ledger.update_endpoint_for_did(
                        did,
                        endpoint,
                        endpoint_type,
                        write_ledger=write_ledger,
                        endorser_did=endorser_did,
                        routing_keys=routing_keys,
                    )
                    if not write_ledger:
                        return attrib_def

        await self.replace_local_did_metadata(did, metadata)
