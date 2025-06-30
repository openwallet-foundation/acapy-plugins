"""Handler for witness operations."""

import logging

from acapy_agent.messaging.base_handler import BaseHandler
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder

from ..did.utils import (
    url_to_domain,
    find_key,
    add_proof
)
from ..did.manager import ControllerManager
from ..did.constants import ALIASES
from .manager import WitnessManager

from ..config.config import get_plugin_config
from .messages import WitnessRequest, WitnessResponse
from .states import WitnessingState

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
        url_decoded_domain = url_to_domain(domain)
        witness_kid = f"webvh:{url_decoded_domain}{ALIASES['witnessKey']}"
        # Attempt to get the witness key for the domain
        witness_key = await find_key(context.profile, witness_kid)
        if not await witness_key:
            # If the key is not found, return an error
            LOGGER.error(
                f"Witness key not found for domain: {witness_kid}. The "
                "administrator must add the key to the wallet that matches the key on"
                " the server."
            )
            return

        # If the key is found, perform witness
        # Note: The witness key is used as the verification method
        witnessed_document = await add_proof(
            document,
            f"did:key:{witness_key}#{witness_key}"
        )
        # If the witness is successful, return a success message
        await responder.send(
            message=WitnessResponse(
                state=WitnessingState.ATTESTED.value,
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
                    state=WitnessingState.PENDING.value,
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
