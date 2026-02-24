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
        resource_type = attested_resource.get("metadata", {}).get("resourceType", "")
        content_tag = attested_resource.get("content", {}).get("tag", "")
        LOGGER.info(
            "WitnessRequestHandler: resourceType=%s content.tag=%s request_id=%s",
            resource_type,
            content_tag,
            request_id,
        )
        if not attested_resource.get("proof", None):
            LOGGER.error("No proof found in attested resource")
            return

        witness = WitnessManager(context.profile)

        config = await get_plugin_config(context.profile)
        connection_id = (
            context.connection_record.connection_id if context.connection_record else ""
        )
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
            # Witness handler: we are always the witness when receiving a request
            role = "self-witness" if not connection_id else "witness"
            await PENDING_RECORDS.save_pending_record(
                context.profile,
                scid,
                attested_resource,
                request_id,
                connection_id or "",
                role=role,
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
        request_id = context.message.request_id

        # Update record state (attested, rejected, etc.)
        try:
            record, connection_id = await PENDING_RECORDS.get_pending_record(
                context.profile, request_id
            )
            if record:
                record["state"] = context.message.state
                async with context.profile.session() as session:
                    await session.handle.replace(
                        PENDING_RECORDS.RECORD_TYPE,
                        request_id,
                        value_json=record,
                        tags={"connection_id": connection_id or ""},
                    )
        except Exception as e:
            LOGGER.warning(f"Could not update pending record state: {e}")

        # Rejected: controller record updated to rejected, then remove
        if context.message.state == WitnessingState.REJECTED.value:
            try:
                await PENDING_RECORDS.remove_pending_record(context.profile, request_id)
            except Exception as e:
                LOGGER.warning(f"Could not remove pending record: {e}")
            return {"status": "ok"}

        # PENDING: witness is holding for manual approval - keep record visible
        if context.message.state == WitnessingState.PENDING.value:
            return {"status": "ok"}

        # Attested: append proof and upload
        if context.message.witness_proof is not None:
            proof = attested_resource.get("proof")
            if isinstance(proof, dict):
                attested_resource["proof"] = [proof]
            elif not isinstance(proof, list):
                attested_resource["proof"] = list(proof) if proof else []
            attested_resource["proof"].append(context.message.witness_proof)
        self._logger.info(attested_resource)

        # Store/update local state BEFORE upload so acapy_agent can store first.
        # upload_resource emits the event that unblocks
        # create_and_register_revocation_registry_definition; if we ran store after
        # upload, we'd race with acapy_agent's store (rotation fails).
        try:
            from ...anoncreds.registry import DIDWebVHRegistry

            registry = DIDWebVHRegistry()
            await registry.store_attested_resource_after_attestation(
                context.profile, attested_resource
            )
        except Exception as e:
            LOGGER.warning("Could not store attested resource after attestation: %s", e)

        await controller.upload_resource(
            attested_resource, context.message.state, request_id
        )

        try:
            await PENDING_RECORDS.remove_pending_record(context.profile, request_id)
        except Exception as e:
            LOGGER.warning(f"Could not remove pending record: {e}")

        return {"status": "ok"}
