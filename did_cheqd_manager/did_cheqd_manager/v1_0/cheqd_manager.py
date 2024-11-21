"""DID manager for Cheqd."""

import logging

from aiohttp import web

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import DIDNotFound
from .resolver.cheqd import CheqdDIDResolver
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.crypto import validate_seed
from .wallet.did_method import CHEQD
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.did_parameters_validation import DIDParametersValidation
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import b58_to_bytes, b64_to_bytes, bytes_to_b64
from .registrar.registrar import DidCheqdRegistrar

LOGGER = logging.getLogger(__name__)


class DidCheqdManager:
    """DID manager for Cheqd."""

    registrar: DidCheqdRegistrar
    resolver: CheqdDIDResolver

    def __init__(self, profile: Profile) -> None:
        """Initialize the Cheqd DID manager."""
        self.profile = profile
        self.registrar = DidCheqdRegistrar()
        self.resolver = CheqdDIDResolver()

    async def sign_requests(wallet, signing_requests, verkey=None):
        """Sign all requests in the siginingRequests array.

        Args:
            wallet: Wallet instance used to sign messages.
            signing_requests: List of signing request dictionaries.
            verkey (optional): Pre-determined verkey to use for signing. \
                If None, retrieve verkey from the wallet.

        Returns:
            List of signed responses, each containing 'kid' and 'signature'.
        """
        signed_responses = []
        for sign_req in signing_requests:
            kid = sign_req.get("kid")
            payload_to_sign = sign_req.get("serializedPayload")
            if verkey:
                # assign verkey to kid in wallet
                await wallet.assign_kid_to_key(verkey, kid)
            if not verkey:
                # retrive verkey from wallet
                key = await wallet.get_key_by_kid(kid)
                if not key:
                    raise ValueError(f"No key found for kid: {kid}")
                verkey = key.verkey
            # sign payload
            signature_bytes = await wallet.sign_message(
                b64_to_bytes(payload_to_sign), verkey
            )

            signed_responses.append(
                {
                    "kid": kid,
                    "signature": bytes_to_b64(signature_bytes),
                }
            )

        return signed_responses

    async def register(self, options: dict) -> dict:
        """Register a Cheqd DID."""
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
                    raise web.HTTPForbidden(reason="No wallet available")

                key = await wallet.create_key(key_type, seed)
                verkey = key.verkey
                verkey_bytes = b58_to_bytes(verkey)
                public_key_hex = verkey_bytes.hex()

                # generate payload
                generate_res = await self.registrar.generate_did_doc(
                    network, public_key_hex
                )
                if generate_res is None:
                    raise WalletError("Error constructing DID Document")

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
                        raise WalletError("No signing requests available for create.")
                    # sign all requests
                    signed_responses = await DidCheqdManager.sign_requests(
                        wallet, signing_requests, verkey
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
                        raise WalletError(
                            f"Error registering DID {publish_did_state.get("reason")}"
                        )
                else:
                    raise WalletError(f"Error registering DID {did_state.get("reason")}")

                # create public did record
                await wallet.create_public_did(CHEQD, key_type, seed, did)

            except WalletError as err:
                return web.json_response({"error": f"Wallet Error: {err}"}, status=400)
            except Exception as e:
                return web.json_response(
                    {"error": f"An unexpected error occurred: {str(e)}"}, status=500
                )
        return web.json_response(
            {
                "did": did,
                "verkey": verkey,
            }
        )

    async def update(self, did: str, didDoc: dict, options: dict) -> dict:
        """Update a Cheqd DID."""

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
                # TODO If registrar supports other operation,
                #       take didDocumentOperation as input
                update_request_res = await self.registrar.update(
                    {
                        "did": did,
                        "didDocumentOperation": ["setDidDocument"],
                        "didDocument": [didDoc],
                    }
                )

                job_id: str = update_request_res.get("jobId")
                did_state = update_request_res.get("didState")

                if did_state.get("state") == "action":
                    signing_requests: dict = did_state.get("signingRequest")
                    if not signing_requests:
                        raise WalletError("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await DidCheqdManager.sign_requests(
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
                        raise WalletError(
                            f"Error publishing DID \
                                update {publish_did_state.get("description")}"
                        )
                else:
                    raise WalletError(f"Error updating DID {did_state.get("reason")}")
            # TODO update new keys to wallet if necessary
            except WalletError as err:
                return web.json_response({"error": f"Wallet Error: {err}"}, status=400)
            except DIDNotFound as err:
                return web.json_response({"error": f"DID Not Found: {err}"}, status=404)
            except Exception as e:
                return web.json_response(
                    {"error": f"An unexpected error occurred: {str(e)}"}, status=500
                )
        return web.json_response(
            {
                "did": did,
                "did_state": publish_did_state.get("state"),
            }
        )

    async def deactivate(self, did: str) -> dict:
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
                    signed_responses = await DidCheqdManager.sign_requests(
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
            except WalletError as err:
                return web.json_response({"error": f"Wallet Error: {err}"}, status=400)
            except DIDNotFound as err:
                return web.json_response({"error": f"DID Not Found: {err}"}, status=404)
            except Exception as e:
                return web.json_response(
                    {"error": f"An unexpected error occurred: {str(e)}"}, status=500
                )
        return web.json_response(
            {
                "did": did,
                "did_document": publish_did_state.get("didDocument"),
                "did_document_metadata": metadata,
            }
        )
