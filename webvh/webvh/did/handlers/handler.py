"""Handler for witness operations."""

import logging

from acapy_agent.messaging.base_handler import BaseHandler
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.keys.manager import MultikeyManager

from ...config.config import get_plugin_config
from ..constants import ALIASES
from ..messages.witness import WitnessRequest, WitnessResponse
from ..controller_manager import ControllerManager
from ..registration_state import RegistrationState
from ..utils import get_url_decoded_domain
from ..witness_manager import WitnessManager

LOGGER = logging.getLogger(__name__)


class WitnessRequestHandler(BaseHandler):
    """Message handler class for witness requests."""

    async def _handle_auto_witness(
        self,
        context: RequestContext,
        responder: BaseResponder,
        proof: dict,
        document: dict,
        parameters: dict,
    ):
        """Handle automatic witness."""
        domain = proof.get("domain")
        url_decoded_domain = get_url_decoded_domain(domain)
        witness_kid = f"webvh:{url_decoded_domain}{ALIASES['witnessKey']}"

        async with context.profile.session() as session:
            # Attempt to get the witness key for the domain
            key_manager = MultikeyManager(session)
            di_manager = DataIntegrityManager(session)
            if not await key_manager.kid_exists(witness_kid):
                # If the key is not found, return an error
                LOGGER.error(
                    f"Witness key not found for domain: {witness_kid}. The "
                    "administrator must add the key to the wallet that matches the key on"
                    " the server."
                )
                return

            # If the key is found, perform witness
            witness_key_info = await key_manager.from_kid(witness_kid)
            witness_key = witness_key_info.get("multikey")
            # Note: The witness key is used as the verification method
            witnessed_document = await di_manager.add_proof(
                document,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{witness_key}#{witness_key}",
                    expires=proof.get("expires"),
                    domain=domain,
                    challenge=proof.get("challenge"),
                ),
            )
        # If the witness is successful, return a success message
        await responder.send(
            message=WitnessResponse(
                state=RegistrationState.ATTESTED.value,
                document=witnessed_document,
                parameters=parameters,
            ),
            connection_id=context.connection_record.connection_id,
        )

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for witness requests."""
        assert isinstance(context.message, WitnessRequest)
        self._logger.debug(
            "Received witness request: %s",
            context.message.document,
        )

        document = context.message.document
        proof = document.get("proof")
        if not proof:
            LOGGER.error("No proof found in log entry")
            return
        proof = proof[0]

        if (await get_plugin_config(context.profile)).get("auto_attest", False):
            await self._handle_auto_witness(
                context, responder, proof, document, context.message.parameters
            )
        else:
            LOGGER.info(
                "Auto attest is not enabled. The administrator must manually "
                "attest the did request document."
            )
            # Save the did request document to the wallet for manual witness
            await WitnessManager(context.profile).save_did_request_doc_for_witnessing(
                document, connection_id=context.connection_record.connection_id
            )
            await responder.send(
                message=WitnessResponse(
                    state=RegistrationState.PENDING.value,
                    document=document,
                    parameters=context.message.parameters,
                ),
                connection_id=context.connection_record.connection_id,
            )


class WitnessResponseHandler(BaseHandler):
    """Message handler class for witness responses."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for witness responses."""
        self._logger.info(
            "Received witness response: %s",
            context.message.state,
        )
        assert isinstance(context.message, WitnessResponse)

        await ControllerManager(context.profile).finish_registration(
            registration_document=context.message.document,
            parameters=context.message.parameters,
            state=context.message.state,
        )
