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
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64
from aiohttp import web

from .base import (
    DidUpdateRequestOptions,
    SubmitSignatureOptions,
    DIDDocumentSchema,
    DidActionState,
)
from .helpers import (
    create_verification_keys,
    create_did_verification_method,
    VerificationMethods,
    create_did_payload,
    CheqdNetwork,
)
from ..did.base import (
    BaseDIDManager,
    CheqdDIDManagerError,
    Secret,
    DidDeactivateRequestOptions,
    DidCreateRequestOptions,
    Options,
)
from ..did_method import CHEQD
from ..resolver.resolver import CheqdDIDResolver
from .registrar import DIDRegistrar

LOGGER = logging.getLogger(__name__)


class CheqdDIDManager(BaseDIDManager):
    """DID manager implementation for did:cheqd."""

    registrar: DIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(
        self,
        profile: Profile,
        registrar_url: str = None,
        resolver_url: str = None,
    ) -> None:
        """Initialize the Cheqd DID manager."""
        super().__init__(profile)
        self.registrar = DIDRegistrar("cheqd", registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)

    async def create(
        self, did_doc: DIDDocumentSchema = None, options: dict = None
    ) -> dict:
        """Create a new Cheqd DID."""
        options = options or {}

        seed = options.get("seed")
        if seed and not self.profile.settings.get("wallet.allow_insecure_seed"):
            raise WalletError("Insecure seed is not allowed")
        if seed:
            seed = validate_seed(seed)

        network = options.get("network") or CheqdNetwork.Testnet.value
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
                public_key_b64 = bytes_to_b64(verkey_bytes)
                verification_method = (
                    options.get("verification_method") or VerificationMethods.Ed255192020
                )

                if did_doc is None:
                    # generate payload
                    verification_keys = create_verification_keys(public_key_b64, network)
                    verification_methods = create_did_verification_method(
                        [verification_method], [verification_keys]
                    )
                    did_document = create_did_payload(
                        verification_methods, [verification_keys]
                    )
                else:
                    did_document = did_doc

                did: str = did_document.get("id")

                # request create did
                create_request_res = await self.registrar.create(
                    DidCreateRequestOptions(
                        didDocument=did_document, options=Options(network=network)
                    )
                )

                job_id = create_request_res.jobId
                did_state = create_request_res.didState
                if isinstance(did_state, DidActionState):
                    if not did_state.signingRequest:
                        raise CheqdDIDManagerError(
                            "No signing requests available for create."
                        )

                    signing_request = next(iter(did_state.signingRequest.values()), None)

                    # Note: This assumes the DID create operation supports only one key
                    kid = signing_request.kid
                    await wallet.assign_kid_to_key(verkey, kid)

                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, did_state.signingRequest
                    )
                    # publish did
                    publish_did_res = await self.registrar.create(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            options=Options(
                                network=network,
                            ),
                            secret=Secret(
                                signingResponse=signed_responses,
                            ),
                        )
                    )
                    publish_did_state = publish_did_res.didState
                    if publish_did_state.state != "finished":
                        raise CheqdDIDManagerError(
                            f"Error registering DID {publish_did_state.reason}"
                        )
                else:
                    raise CheqdDIDManagerError(
                        f"Error registering DID {did_state.reason}"
                    )

                # create public did record
                await wallet.create_public_did(CHEQD, key_type, seed, did)
                await wallet.assign_kid_to_key(verkey, kid)
            except Exception as ex:
                raise ex
        return {
            "did": did,
            "verkey": verkey,
            "didDocument": publish_did_state.didDocument.dict(),
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
                    DidUpdateRequestOptions(
                        did=did,
                        didDocumentOperation=["setDidDocument"],
                        didDocument=[did_doc],
                    )
                )

                job_id = update_request_res.jobId
                did_state = update_request_res.didState

                if isinstance(did_state, DidActionState):
                    signing_requests = did_state.signingRequest
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )

                    # submit signed update
                    publish_did_res = await self.registrar.update(
                        SubmitSignatureOptions(
                            jobId=job_id, secret=Secret(signingResponse=signed_responses)
                        )
                    )
                    publish_did_state = publish_did_res.didState

                    if publish_did_state.state != "finished":
                        raise CheqdDIDManagerError(
                            f"Error publishing DID \
                                update {publish_did_state.reason}"
                        )
                else:
                    raise CheqdDIDManagerError(f"Error updating DID {did_state.reason}")
            # TODO update new keys to wallet if necessary
            except Exception as ex:
                raise ex

        return {"did": did, "didDocument": publish_did_state.didDocument.dict()}

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
                deactivate_request_res = await self.registrar.deactivate(
                    DidDeactivateRequestOptions(did=did)
                )

                job_id: str = deactivate_request_res.jobId
                did_state = deactivate_request_res.didState

                if isinstance(did_state, DidActionState):
                    signing_requests = did_state.signingRequest
                    if not signing_requests:
                        raise WalletError("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    # submit signed deactivate
                    publish_did_res = await self.registrar.deactivate(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            secret=Secret(
                                signingResponse=signed_responses,
                            ),
                        )
                    )

                    publish_did_state = publish_did_res.didState

                    if publish_did_state.state != "finished":
                        raise WalletError(
                            f"Error publishing DID \
                                deactivate {publish_did_state.reason}"
                        )
                else:
                    raise WalletError(f"Error deactivating DID {did_state.reason}")
                # update local did metadata
                did_info = await wallet.get_local_did(did)
                metadata = {**did_info.metadata, "deactivated": True}
                await wallet.replace_local_did_metadata(did, metadata)
            except Exception as ex:
                raise ex
        return {
            "did": did,
            "didDocument": publish_did_state.didDocument.dict(),
            "didDocumentMetadata": metadata,
        }
