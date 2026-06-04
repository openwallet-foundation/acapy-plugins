"""Notification endpoint for OID4VCI."""

import json
import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs
from marshmallow import fields

from ..models.exchange import OID4VCIExchangeRecord
from .token import check_token

LOGGER = logging.getLogger(__name__)

_VALID_EVENTS = {"credential_accepted", "credential_failure", "credential_deleted"}


class NotificationSchema(OpenAPISchema):
    """Schema for notification endpoint (used for documentation only)."""

    notification_id = fields.Str(
        required=True,
        metadata={"description": "Notification identifier", "example": "3fwe98js"},
    )
    event = fields.Str(
        required=True,
        metadata={
            "description": (
                "Type of the notification event, value is one of: "
                "'credential_accepted', 'credential_failure', or 'credential_deleted'"
            ),
            "example": "credential_accepted",
        },
    )
    event_description = fields.Str(
        required=False, metadata={"description": "Human-readable ASCII [USASCII] text"}
    )


def _notif_error(status: int, error: str, description: str) -> web.HTTPException:
    """Return an HTTPException with a JSON body for notification errors.

    OID4VCI 1.0 §11 notification errors use the same error code vocabulary as
    the credential endpoint (§7.3).  Use 'invalid_credential_request' as the
    catch-all for malformed notification requests.
    """
    body = json.dumps({"error": error, "error_description": description})
    if status == 400:
        return web.HTTPBadRequest(text=body, content_type="application/json")
    if status == 401:
        return web.HTTPUnauthorized(text=body, content_type="application/json")
    return web.HTTPBadRequest(text=body, content_type="application/json")


@docs(tags=["oid4vci"], summary="Send a notification to the user")
async def receive_notification(request: web.Request):
    """Notification endpoint (OID4VCI 1.0 §11).

    OID4VCI 1.0 requires HTTP 400 for all notification errors.  We do NOT use
    @request_schema because aiohttp_apispec returns 422 for schema validation
    failures, which does not conform to the spec.
    """
    try:
        return await _receive_notification_inner(request)
    except web.HTTPException as exc:
        if exc.status in (401, 403):
            raise
        # Return spec-compliant JSON error body (avoid aiohttp middleware stripping)
        err_body: dict = {}
        if exc.text:
            try:
                err_body = json.loads(exc.text)
            except (json.JSONDecodeError, ValueError):
                err_body = {
                    "error": "invalid_notification_request",
                    "error_description": exc.reason or "Bad Request",
                }
        else:
            err_body = {
                "error": "invalid_notification_request",
                "error_description": exc.reason or "Bad Request",
            }
        return web.json_response(err_body, status=exc.status)


async def _receive_notification_inner(request: web.Request) -> web.Response:
    """Inner implementation; raises HTTPException on all errors."""
    # Auth check first — raises HTTPUnauthorized on failure
    context: AdminRequestContext = request["context"]
    await check_token(context, request.headers.get("Authorization"))

    try:
        body = await request.json()
    except Exception as exc:
        raise _notif_error(
            400,
            "invalid_credential_request",
            "Request body must be valid JSON",
        ) from exc

    LOGGER.debug("Notification request: %s", body)

    # Manually validate required fields — OID4VCI 1.0 §11 requires 400 for errors.
    notification_id = body.get("notification_id")
    event = body.get("event")
    if not notification_id or not event:
        missing = [f for f in ("notification_id", "event") if not body.get(f)]
        raise _notif_error(
            400,
            "invalid_credential_request",
            f"Missing required field(s): {', '.join(missing)}",
        )

    if event not in _VALID_EVENTS:
        raise _notif_error(
            400,
            "invalid_credential_request",
            f"event must be one of: {', '.join(sorted(_VALID_EVENTS))}",
        )

    event_desc = body.get("event_description")

    async with context.profile.session() as session:
        try:
            record = await OID4VCIExchangeRecord.retrieve_by_notification_id(
                session, notification_id
            )
            if not record:
                raise _notif_error(
                    400, "invalid_credential_request", "Unknown notification_id"
                )
            if event == "credential_accepted":
                record.state = OID4VCIExchangeRecord.STATE_ACCEPTED
            elif event == "credential_failure":
                record.state = OID4VCIExchangeRecord.STATE_FAILED
            elif event == "credential_deleted":
                record.state = OID4VCIExchangeRecord.STATE_DELETED
            record.notification_event = {"event": event, "description": event_desc}
            await record.save(session, reason="Updated by notification")
        except web.HTTPException:
            raise
        except (StorageError, BaseModelError, StorageNotFoundError) as err:
            raise _notif_error(400, "invalid_credential_request", err.roll_up) from err

    return web.Response(status=204)
