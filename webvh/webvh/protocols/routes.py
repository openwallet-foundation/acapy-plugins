"""DID Webvh protocol routes module."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.responder import BaseResponder
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema

from .attested_resource.messages import WitnessResponse as AttestedResourceWitnessResponse
from .attested_resource.record import PendingAttestedResourceRecord
from .log_entry.messages import WitnessResponse as LogEntryWitnessResponse
from .log_entry.record import PendingLogEntryRecord
from .states import WitnessingState
from ..did.models.operations import (
    RecordTypeEnum,
    RecordTypeMatchInfoSchema,
    RecordTypeRecordIdMatchInfoSchema,
)
from ..did.witness import WitnessManager
from ..did.exceptions import WitnessError

LOGGER = logging.getLogger(__name__)

RECORD_TYPES = {
    RecordTypeEnum.LOG_ENTRY.value: PendingLogEntryRecord(),
    RecordTypeEnum.ATTESTED_RESOURCE.value: PendingAttestedResourceRecord(),
}

# Only witness or self-witness can approve a pending request
WITNESS_ROLES = ("witness", "self-witness")


@docs(tags=["did-webvh"], summary="Get all pending witness requests")
@match_info_schema(RecordTypeMatchInfoSchema())
@tenant_authentication
async def get_pending_witness_requests(request: web.BaseRequest):
    """Get all pending witness requests (works for both controller and witness)."""
    context: AdminRequestContext = request["context"]
    record_type_str = request.match_info["record_type"]
    PENDING_RECORDS = RECORD_TYPES.get(record_type_str, None)
    if not PENDING_RECORDS:
        return web.json_response(
            {"status": "error", "message": f"Unknown record type: {record_type_str}"},
            status=400,
        )
    pending_witness_requests = await PENDING_RECORDS.get_pending_records(context.profile)
    return web.json_response({"results": pending_witness_requests})


@docs(tags=["did-webvh"], summary="Approve a pending witness request")
@match_info_schema(RecordTypeRecordIdMatchInfoSchema())
@tenant_authentication
async def approve_pending_witness_request(request: web.BaseRequest):
    """Approve a pending attested resource."""
    context: AdminRequestContext = request["context"]
    manager = WitnessManager(context.profile)

    try:
        record_id = request.match_info["record_id"]
        record_type_str = request.match_info["record_type"]
        PENDING_RECORDS = RECORD_TYPES.get(record_type_str, None)
        if not PENDING_RECORDS:
            return web.json_response(
                {"status": "error", "message": f"Unknown record type: {record_type_str}"},
                status=400,
            )

        record, connection_id = await PENDING_RECORDS.get_pending_record(
            context.profile, record_id
        )
        if record is None:
            raise WitnessError("Failed to find pending document.")

        role = record.get("role", "")
        if role not in WITNESS_ROLES:
            return web.json_response(
                {
                    "status": "error",
                    "message": (
                        "Only the witness or self-witness can approve a pending request."
                    ),
                },
                status=403,
            )

        if record_type_str == RecordTypeEnum.ATTESTED_RESOURCE.value:
            await manager.approve_attested_resource(
                record.get("record", None), connection_id, record_id
            )
        elif record_type_str == RecordTypeEnum.LOG_ENTRY.value:
            await manager.approve_log_entry(
                record.get("record", None), connection_id, record_id
            )

        await PENDING_RECORDS.remove_pending_record(context.profile, record_id)

        return web.json_response({"status": "success", "message": "Witness successful."})

    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject / remove a pending witness request")
@match_info_schema(RecordTypeRecordIdMatchInfoSchema())
@tenant_authentication
async def reject_pending_witness_request(request: web.BaseRequest):
    """Reject (witness) or remove (controller) a pending witness request."""
    context: AdminRequestContext = request["context"]

    try:
        record_id = request.match_info["record_id"]
        record_type_str = request.match_info["record_type"]
        PENDING_RECORDS = RECORD_TYPES.get(record_type_str, None)
        if not PENDING_RECORDS:
            return web.json_response(
                {"status": "error", "message": f"Unknown record type: {record_type_str}"},
                status=400,
            )

        # When witness rejects, notify the controller so they can update their record
        try:
            record, connection_id = await PENDING_RECORDS.get_pending_record(
                context.profile, record_id
            )
            if record and record.get("role") in WITNESS_ROLES and connection_id:
                document = record.get("record", {})
                WitnessResponseCls = (
                    LogEntryWitnessResponse
                    if record_type_str == RecordTypeEnum.LOG_ENTRY.value
                    else AttestedResourceWitnessResponse
                )
                responder = context.profile.inject(BaseResponder)
                await responder.send(
                    message=WitnessResponseCls(
                        state=WitnessingState.REJECTED.value,
                        document=document,
                        request_id=record_id,
                    ),
                    connection_id=connection_id,
                )
        except Exception as e:
            LOGGER.warning("Could not notify controller of rejection: %s", e)

        return web.json_response(
            await PENDING_RECORDS.remove_pending_record(context.profile, record_id)
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})
