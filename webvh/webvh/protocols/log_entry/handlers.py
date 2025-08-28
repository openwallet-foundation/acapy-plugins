"""Handler for witness operations."""

import logging

from acapy_agent.messaging.base_handler import BaseHandler
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder

from ...did.manager import ControllerManager
from ...did.witness import WitnessManager

from ...config.config import get_plugin_config
from ..states import WitnessingState
from .messages import WitnessRequest, WitnessResponse
from .record import PendingLogEntryRecord

LOGGER = logging.getLogger(__name__)
PENDING_RECORDS = PendingLogEntryRecord()


class WitnessRequestHandler(BaseHandler):
    """Message handler class for witness requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for witness requests."""
        assert isinstance(context.message, WitnessRequest)
        self._logger.debug(
            "Received witness request: %s",
            context.message.document,
        )

        log_entry = context.message.document
        request_id = context.message.request_id
        if not log_entry.get("proof", None):
            LOGGER.error("No proof found in log entry")
            return

        witness = WitnessManager(context.profile)

        config = await get_plugin_config(context.profile)
        connection_id = context.connection_record.connection_id
        if config.get("auto_attest", False):
            witness_signature = await witness.sign_log_version(log_entry.get("versionId"))
            await responder.send(
                message=WitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=log_entry,
                    witness_proof=witness_signature.get("proof")[0],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        else:
            LOGGER.info(
                "Auto attest is not enabled. The administrator must manually "
                "attest the did request document."
            )
            # Save the document to the wallet for manual witness
            scid = log_entry.get("state").get("id").split(":")[2]
            await PENDING_RECORDS.save_pending_record(
                context.profile, scid, log_entry, request_id, connection_id
            )

            await responder.send(
                message=WitnessResponse(
                    state=WitnessingState.PENDING.value,
                    document=log_entry,
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

        log_entry = context.message.document
        controller = ControllerManager(context.profile)

        witness_signature = {
            "versionId": log_entry.get("versionId"),
            "proof": [context.message.witness_proof],
        }

        # Call finish_create for first entry
        if log_entry.get("versionId")[0] == "1":
            await controller.finish_create(
                initial_log_entry=log_entry,
                witness_signature=witness_signature,
                state=context.message.state,
                record_id=context.message.request_id,
            )

        # Call finish_update for subsequent entry
        else:
            await controller.finish_update(
                initial_log_entry=log_entry,
                witness_signature=witness_signature,
                state=context.message.state,
                record_id=context.message.request_id,
            )

        return {"status": "ok"}
