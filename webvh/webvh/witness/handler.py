"""Handler for witness operations."""

import logging

from acapy_agent.messaging.base_handler import BaseHandler
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder

from ..did.utils import url_to_domain, find_key, add_proof, is_log_entry, is_attested_resource
from ..did.manager import ControllerManager
from ..did.constants import ALIASES
from .manager import WitnessManager

from ..config.config import get_plugin_config, get_server_domain
from .messages import WitnessRequest, WitnessResponse
from .states import WitnessingState

LOGGER = logging.getLogger(__name__)


class WitnessRequestHandler(BaseHandler):
    """Message handler class for witness requests."""

    async def _handle_auto_witness(
        self,
        context: RequestContext,
        responder: BaseResponder,
        document: dict,
    ):
        """Handle automatic witness."""
        
        witness_signature = await WitnessManager(context.profile).sign_log_version(
            document.get("versionId")
        )
        # If the witness call is successful, return a success message
        await responder.send(
            message=WitnessResponse(
                state=WitnessingState.ATTESTED.value,
                document=document,
                witness_proof=witness_signature.get('proof')[0],
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
        if not document.get("proof", None):
            LOGGER.error("No proof found in document")
            return

        config = await get_plugin_config(context.profile)
        if config.get("auto_attest", False):
            await self._handle_auto_witness(context, responder, document)

        else:
            LOGGER.info(
                "Auto attest is not enabled. The administrator must manually "
                "attest the did request document."
            )
        
            # We define if the request is for a log entry or an attested resource
            # Save the document to the wallet for manual witness
            witness = WitnessManager(context.profile)
            connection_id = context.connection_record.connection_id
            if is_log_entry(document):
                await witness.save_log_entry(document, connection_id)
            
            elif is_attested_resource(document):
                await witness.save_attested_resource(document, connection_id)
            
            else:
                LOGGER.error("Unknown document type")
                return
            
            await responder.send(
                WitnessResponse(
                    state=WitnessingState.PENDING.value,
                    document=document
                ),
                connection_id
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
        
        document = context.message.document
        controller = ControllerManager(context.profile)
        
        # For a log entry, we create a witness file with the version ID and the proof
        if is_log_entry(document):
            
            witness_signature = {
                'versionId': document.get('versionId'),
                'proof': [context.message.witness_proof]
            }
            # Call finish_create for first entry
            if document.get('versionId')[0] == '1':
                await controller.finish_create(
                    initial_log_entry=document,
                    witness_signature=witness_signature,
                    state=context.message.state,
                )
            # Call finish_update for subsequent entry
            else:
                await controller.finish_update(
                    initial_log_entry=document,
                    witness_signature=witness_signature,
                    state=context.message.state,
                )
        
        # For an attested resource, we append the proof 
        elif is_attested_resource(document):
            # For an attested resource, we append the proof
            document['proof'].append(context.message.proof)
            await controller.upload_resource(document)


