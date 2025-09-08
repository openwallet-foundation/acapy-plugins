"""DID Webvh protocol routes module."""

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from aiohttp_apispec import docs
from .attested_resource.record import PendingAttestedResourceRecord
from .log_entry.record import PendingLogEntryRecord
from ..did.witness import WitnessManager
from ..did.exceptions import WitnessError

RECORD_TYPES = {
    "attested-resource": PendingAttestedResourceRecord(),
    "log-entry": PendingLogEntryRecord(),
}


@docs(tags=["did-webvh"], summary="Get all pending witness requests")
@tenant_authentication
async def get_pending_witness_requests(request: web.BaseRequest):
    """Get all pending witness requests."""
    context: AdminRequestContext = request["context"]
    request_type = request.match_info["request_type"]
    PENDING_RECORDS = RECORD_TYPES.get(request_type, None)
    pending_witness_requests = await PENDING_RECORDS.get_pending_records(context.profile)
    return web.json_response({"results": pending_witness_requests})


@docs(tags=["did-webvh"], summary="Approve a pending witness request")
@tenant_authentication
async def approve_pending_witness_request(request: web.BaseRequest):
    """Approve a pending attested resource."""
    context: AdminRequestContext = request["context"]
    manager = WitnessManager(context.profile)

    try:
        request_id = request.match_info["request_id"]
        request_type = request.match_info["request_type"]
        PENDING_RECORDS = RECORD_TYPES.get(request_type, None)

        record, connection_id = await PENDING_RECORDS.get_pending_record(
            context.profile, request_id
        )
        if record is None:
            raise WitnessError("Failed to find pending document.")

        if request_type == "attested-resource":
            await manager.approve_attested_resource(
                record.get("record", None), connection_id, request_id
            )
        elif request_type == "log-entry":
            await manager.approve_log_entry(
                record.get("record", None), connection_id, request_id
            )

        await PENDING_RECORDS.remove_pending_record(context.profile, request_id)

        return web.json_response({"status": "success", "message": "Witness successful."})

    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})


@docs(tags=["did-webvh"], summary="Reject a pending witness request")
@tenant_authentication
async def reject_pending_witness_request(request: web.BaseRequest):
    """Reject a pending witness request."""
    context: AdminRequestContext = request["context"]

    try:
        request_id = request.match_info["request_id"]
        request_type = request.match_info["request_type"]
        PENDING_RECORDS = RECORD_TYPES.get(request_type, None)
        return web.json_response(
            await PENDING_RECORDS.remove_pending_record(context.profile, request_id)
        )
    except WitnessError as err:
        return web.json_response({"status": "error", "message": str(err)})
