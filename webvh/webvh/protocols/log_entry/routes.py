"""DID Webvh protocol routes module."""

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from aiohttp_apispec import docs, querystring_schema
from ...did.models.operations import WebvhRecordIdQueryStringSchema
from .record import PendingLogEntryRecord
from ...did.witness import WitnessManager
from ...did.exceptions import WitnessError

PENDING_RECORDS = PendingLogEntryRecord()


@docs(tags=["did-webvh"], summary="Get all pending log entries")
@tenant_authentication
async def get_pending_log_entries(request: web.BaseRequest):
    """Get all pending log entries."""
    context: AdminRequestContext = request["context"]
    pending_log_entries = await PENDING_RECORDS.get_pending_records(context.profile)
    return web.json_response({"results": pending_log_entries})


@docs(tags=["did-webvh"], summary="Approve a pending log entry")
@querystring_schema(WebvhRecordIdQueryStringSchema())
@tenant_authentication
async def approve_pending_log_entry(request: web.BaseRequest):
    """Approve a pending log entry."""
    context: AdminRequestContext = request["context"]

    try:
        record, connection_id = await PENDING_RECORDS.get_pending_record(
            context.profile, request.query.get("record_id")
        )
        if record is None:
            raise WitnessError("Failed to find pending document.")

        await WitnessManager(context.profile).approve_log_entry(
            record.get("record", None), connection_id, request.query.get("record_id")
        )

        await PENDING_RECORDS.remove_pending_record(
            context.profile, record.get("record_id", None)
        )

        return web.json_response({"status": "success", "message": "Witness successful."})
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject a pending log entry")
@querystring_schema(WebvhRecordIdQueryStringSchema())
@tenant_authentication
async def reject_pending_log_entry(request: web.BaseRequest):
    """Reject a pending log entry."""
    context: AdminRequestContext = request["context"]

    try:
        return web.json_response(
            await PENDING_RECORDS.remove_pending_record(
                context.profile, request.query.get("record_id")
            )
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})
