"""DID Webvh protocol routes module."""

import enum
import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from aiohttp_apispec import docs
from .attested_resource.record import PendingAttestedResourceRecord
from .log_entry.record import PendingLogEntryRecord
from ..did.witness import WitnessManager
from ..did.exceptions import WitnessError

LOGGER = logging.getLogger(__name__)


class WitnessRecordType(str, enum.Enum):
    """Enum for witness request record types."""

    ATTESTED_RESOURCE = "attested-resource"
    LOG_ENTRY = "log-entry"


RECORD_TYPES = {
    WitnessRecordType.ATTESTED_RESOURCE.value: PendingAttestedResourceRecord(),
    WitnessRecordType.LOG_ENTRY.value: PendingLogEntryRecord(),
}


@docs(
    tags=["did-webvh"],
    summary="Get all pending witness requests",
    parameters=[
        {
            "in": "path",
            "name": "record_type",
            "required": True,
            "schema": {
                "type": "string",
                "enum": [e.value for e in WitnessRecordType],
            },
            "description": "Type of witness request record",
            "example": WitnessRecordType.ATTESTED_RESOURCE.value,
        }
    ],
)
@tenant_authentication
async def get_pending_witness_requests(request: web.BaseRequest):
    """Get all pending witness requests."""
    context: AdminRequestContext = request["context"]
    record_type_str = request.match_info["record_type"]
    try:
        record_type = WitnessRecordType(record_type_str)
    except ValueError:
        raise WitnessError(
            f"Invalid record type: {record_type_str}. "
            f"Must be one of: {[e.value for e in WitnessRecordType]}"
        )
    PENDING_RECORDS = RECORD_TYPES.get(record_type.value, None)
    if PENDING_RECORDS is None:
        raise WitnessError(f"Record type {record_type.value} not supported.")
    pending_witness_requests = await PENDING_RECORDS.get_pending_records(context.profile)
    return web.json_response({"results": pending_witness_requests})


@docs(
    tags=["did-webvh"],
    summary="Approve a pending witness request",
    parameters=[
        {
            "in": "path",
            "name": "record_type",
            "required": True,
            "schema": {
                "type": "string",
                "enum": [e.value for e in WitnessRecordType],
            },
            "description": "Type of witness request record",
            "example": WitnessRecordType.ATTESTED_RESOURCE.value,
        },
        {
            "in": "path",
            "name": "record_id",
            "required": True,
            "schema": {"type": "string"},
            "description": "ID of the pending witness request record",
        },
    ],
)
@tenant_authentication
async def approve_pending_witness_request(request: web.BaseRequest):
    """Approve a pending attested resource."""
    context: AdminRequestContext = request["context"]
    manager = WitnessManager(context.profile)

    try:
        record_id = request.match_info["record_id"]
        record_type_str = request.match_info["record_type"]
        try:
            record_type = WitnessRecordType(record_type_str)
        except ValueError:
            raise WitnessError(
                f"Invalid record type: {record_type_str}. "
                f"Must be one of: {[e.value for e in WitnessRecordType]}"
            )
        PENDING_RECORDS = RECORD_TYPES.get(record_type.value, None)
        if PENDING_RECORDS is None:
            raise WitnessError(f"Record type {record_type.value} not supported.")

        record, connection_id = await PENDING_RECORDS.get_pending_record(
            context.profile, record_id
        )
        if record is None:
            raise WitnessError("Failed to find pending document.")

        if record_type == WitnessRecordType.ATTESTED_RESOURCE:
            await manager.approve_attested_resource(
                record.get("record", None), connection_id, record_id
            )
        elif record_type == WitnessRecordType.LOG_ENTRY:
            await manager.approve_log_entry(
                record.get("record", None), connection_id, record_id
            )

        await PENDING_RECORDS.remove_pending_record(context.profile, record_id)

        LOGGER.info(f"Witness successful for {record_type.value} record {record_id}")
        return web.json_response({"status": "success", "message": "Witness successful."})

    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(
    tags=["did-webvh"],
    summary="Reject a pending witness request",
    parameters=[
        {
            "in": "path",
            "name": "record_type",
            "required": True,
            "schema": {
                "type": "string",
                "enum": [e.value for e in WitnessRecordType],
            },
            "description": "Type of witness request record",
            "example": WitnessRecordType.ATTESTED_RESOURCE.value,
        },
        {
            "in": "path",
            "name": "record_id",
            "required": True,
            "schema": {"type": "string"},
            "description": "ID of the pending witness request record",
        },
    ],
)
@tenant_authentication
async def reject_pending_witness_request(request: web.BaseRequest):
    """Reject a pending witness request."""
    context: AdminRequestContext = request["context"]

    try:
        record_id = request.match_info["record_id"]
        record_type_str = request.match_info["record_type"]
        try:
            record_type = WitnessRecordType(record_type_str)
        except ValueError:
            raise WitnessError(
                f"Invalid record type: {record_type_str}. "
                f"Must be one of: {[e.value for e in WitnessRecordType]}"
            )
        PENDING_RECORDS = RECORD_TYPES.get(record_type.value, None)
        if PENDING_RECORDS is None:
            raise WitnessError(f"Record type {record_type.value} not supported.")
        return web.json_response(
            await PENDING_RECORDS.remove_pending_record(context.profile, record_id)
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})
