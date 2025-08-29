"""Handler for witness operations."""

import copy
import logging

from acapy_agent.messaging.base_handler import BaseHandler
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder

from ...did.utils import add_proof
from ...did.manager import ControllerManager
from ...did.witness import WitnessManager

from ...config.config import get_plugin_config
from ..states import WitnessingState
from .messages import WitnessRequest, WitnessResponse
from .record import PendingAttestedResourceRecord

LOGGER = logging.getLogger(__name__)

PENDING_RECORDS = PendingAttestedResourceRecord()


class WitnessRequestHandler(BaseHandler):
    """Message handler class for witness requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for witness requests."""
        assert isinstance(context.message, WitnessRequest)
        self._logger.debug(
            "Received witness request: %s",
            context.message.document,
        )

        attested_resource = context.message.document
        request_id = context.message.request_id
        if not attested_resource.get("proof", None):
            LOGGER.error("No proof found in attested resource")
            return

        witness = WitnessManager(context.profile)

        config = await get_plugin_config(context.profile)
        connection_id = context.connection_record.connection_id
        if config.get("auto_attest", False):
            witness_key = await witness.get_witness_key()
            witness_signature = await add_proof(
                context.profile,
                copy.deepcopy(attested_resource),
                f"did:key:{witness_key}#{witness_key}",
            )
            await responder.send(
                message=WitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=attested_resource,
                    witness_proof=witness_signature.get("proof")[-1],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        else:
            LOGGER.info(
                "Auto attest is not enabled. The administrator must manually "
                "attest the did request document."
            )

            # We define if the request is for a log entry or an attested resource
            # Save the document to the wallet for manual witness
            scid = attested_resource.get("id").split(":")[2]
            await PENDING_RECORDS.save_pending_record(
                context.profile, scid, attested_resource, request_id, connection_id
            )

            await responder.send(
                message=WitnessResponse(
                    state=WitnessingState.PENDING.value,
                    document=attested_resource,
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        return {"status": "ok"}


class WitnessResponseHandler(BaseHandler):
    """Message handler class for witness responses."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for witness responses."""
        self._logger.info(
            "Received witness response: %s",
            context.message.state,
        )
        assert isinstance(context.message, WitnessResponse)

        attested_resource = context.message.document
        controller = ControllerManager(context.profile)

        # For an attested resource, we append the proof
        attested_resource["proof"].append(context.message.witness_proof)
        self._logger.info(attested_resource)
        await controller.upload_resource(
            attested_resource, context.message.state, context.message.request_id
        )

        return {"status": "ok"}
