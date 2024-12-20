"""DID Manager for Cheqd."""

import logging

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import DIDNotFound
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.crypto import validate_seed
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.did_parameters_validation import DIDParametersValidation
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import b58_to_bytes
from aiohttp import web

from ..did.base import BaseDIDManager, CheqdDIDManagerError
from ..did_method import CHEQD
from ..resolver.resolver import CheqdDIDResolver
from .registrar import CheqdDIDRegistrar

LOGGER = logging.getLogger(__name__)


class CheqdDIDManager(BaseDIDManager):
    """DID manager implementation for did:cheqd."""

    registrar: CheqdDIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(
        self,
        profile: Profile,
        registrar_url: str = None,
        resolver_url: str = None,
    ) -> None:
        """Initialize the Cheqd DID manager."""
        super().__init__(profile)
        self.registrar = CheqdDIDRegistrar(registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)

    async def create(self, did_doc: dict = None, options: dict = None) -> dict:
        """Create a new Cheqd DID."""
        options = options or {}

        seed = options.get("seed")
        if seed and not self.profile.settings.get("wallet.allow_insecure_seed"):
            raise WalletError("Insecure seed is not allowed")
        if seed:
            seed = validate_seed(seed)

        network = options.get("network") or "testnet"
        key_type = ED25519

        did_validation = DIDParametersValidation(self.profile.inject(DIDMethods))
        did_validation.validate_key_type(CHEQD, key_type)

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise WalletError(reason="No wallet available")

                key = await wallet.create_key(key_type, seed)
                verkey = key.verkey
                verkey_bytes = b58_to_bytes(verkey)
                public_key_hex = verkey_bytes.hex()

                # generate payload
                generate_res = await self.registrar.generate_did_doc(
                    network, public_key_hex
                )
                if generate_res is None:
                    raise CheqdDIDManagerError("Error constructing DID Document")

                did_document = generate_res.get("didDoc")
                did: str = did_document.get("id")

                # request create did
                create_request_res = await self.registrar.create(
                    {"didDocument": did_document, "network": network}
                )

                job_id: str = create_request_res.get("jobId")
                did_state = create_request_res.get("didState")
                if did_state.get("state") == "action":
                    signing_requests: dict = did_state.get("signingRequest")
                    if not signing_requests:
                        raise CheqdDIDManagerError(
                            "No signing requests available for create."
                        )

                    # Note: This assumes did create operation supports only one did
                    kid: str = signing_requests[0].get("kid")
                    await wallet.assign_kid_to_key(verkey, kid)
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    # publish did
                    publish_did_res = await self.registrar.create(
                        {
                            "jobId": job_id,
                            "network": network,
                            "secret": {
                                "signingResponse": signed_responses,
                            },
                        }
                    )
                    publish_did_state = publish_did_res.get("didState")
                    if publish_did_state.get("state") != "finished":
                        raise CheqdDIDManagerError(
                            f"Error registering DID {publish_did_state.get("reason")}"
                        )
                else:
                    raise CheqdDIDManagerError(
                        f"Error registering DID {did_state.get("reason")}"
                    )

                # create public did record
                await wallet.create_public_did(CHEQD, key_type, seed, did)
                await wallet.assign_kid_to_key(verkey, kid)
            except Exception as ex:
                raise ex
        return {
            "did": did,
            "verkey": verkey,
            "didDocument": publish_did_state.get("didDocument"),
        }

    async def update(self, did: str, did_doc: dict, options: dict = None) -> dict:
        """Update a Cheqd DID."""

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise web.HTTPForbidden(reason="No wallet available")

                # Resolve the DID and ensure it is not deactivated and is valid
                curr_did_doc = await self.resolver.resolve(self.profile, did)
                if not curr_did_doc or curr_did_doc.get("deactivated"):
                    raise DIDNotFound("DID is already deactivated or not found.")

                # request deactivate did
                # TODO If registrar supports other operation,
                #       take didDocumentOperation as input
                update_request_res = await self.registrar.update(
                    {
                        "did": did,
                        "didDocumentOperation": ["setDidDocument"],
                        "didDocument": [did_doc],
                    }
                )

                job_id: str = update_request_res.get("jobId")
                did_state = update_request_res.get("didState")

                if did_state.get("state") == "action":
                    signing_requests: dict = did_state.get("signingRequest")
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )

                    # submit signed update
                    publish_did_res = await self.registrar.update(
                        {
                            "jobId": job_id,
                            "secret": {
                                "signingResponse": signed_responses,
                            },
                        }
                    )
                    publish_did_state = publish_did_res.get("didState")

                    if publish_did_state.get("state") != "finished":
                        raise CheqdDIDManagerError(
                            f"Error publishing DID \
                                update {publish_did_state.get("description")}"
                        )
                else:
                    raise CheqdDIDManagerError(
                        f"Error updating DID {did_state.get("reason")}"
                    )
            # TODO update new keys to wallet if necessary
            except Exception as ex:
                raise ex

        return {"did": did, "didDocument": publish_did_state.get("didDocument")}

    async def deactivate(self, did: str, options: dict = None) -> dict:
        """Deactivate a Cheqd DID."""
        LOGGER.debug("Deactivate did: %s", did)

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise web.HTTPForbidden(reason="No wallet available")
                # Resolve the DID and ensure it is not deactivated and is valid
                did_doc = await self.resolver.resolve(self.profile, did)
                if not did_doc or did_doc.get("deactivated"):
                    raise DIDNotFound("DID is already deactivated or not found.")

                # request deactivate did
                deactivate_request_res = await self.registrar.deactivate({"did": did})

                job_id: str = deactivate_request_res.get("jobId")
                did_state = deactivate_request_res.get("didState")

                if did_state.get("state") == "action":
                    signing_requests = did_state.get("signingRequest")
                    if not signing_requests:
                        raise WalletError("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    # submit signed deactivate
                    publish_did_res = await self.registrar.deactivate(
                        {
                            "jobId": job_id,
                            "secret": {
                                "signingResponse": signed_responses,
                            },
                        }
                    )

                    publish_did_state = publish_did_res.get("didState")

                    if publish_did_state.get("state") != "finished":
                        raise WalletError(
                            f"Error publishing DID \
                                deactivate {publish_did_state.get("description")}"
                        )
                else:
                    raise WalletError(f"Error deactivating DID {did_state.get("reason")}")
                # update local did metadata
                did_info = await wallet.get_local_did(did)
                metadata = {**did_info.metadata, "deactivated": True}
                await wallet.replace_local_did_metadata(did, metadata)
            except Exception as ex:
                raise ex
        return {
            "did": did,
            "did_document": publish_did_state.get("didDocument"),
            "did_document_metadata": metadata,
        }
