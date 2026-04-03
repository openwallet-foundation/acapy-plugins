"""Notification endpoint."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
)
from marshmallow import fields

from .token import check_token
from ..models.exchange import OID4VCIExchangeRecord

LOGGER = logging.getLogger(__name__)


class NotificationSchema(OpenAPISchema):
    """Schema for notification endpoint."""

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


@docs(tags=["oid4vci"], summary="Send a notification to the user")
@request_schema(NotificationSchema())
async def receive_notification(request: web.Request):
    """Send a notification to the user."""
    body = await request.json()
    LOGGER.debug(f"Notification request: {body}")

    context: AdminRequestContext = request["context"]
    if not await check_token(context, request.headers.get("Authorization")):
        raise web.HTTPUnauthorized(reason="invalid_token")

    async with context.profile.session() as session:
        try:
            record = await OID4VCIExchangeRecord.retrieve_by_notification_id(
                session, body.get("notification_id", None)
            )
            if not record:
                raise web.HTTPBadRequest(reason="invalid_notification_id")
            event = body.get("event", None)
            event_desc = body.get("event_description", None)
            if event == "credential_accepted":
                record.state = OID4VCIExchangeRecord.STATE_ACCEPTED
            elif event == "credential_failure":
                record.state = OID4VCIExchangeRecord.STATE_FAILED
            elif event == "credential_deleted":
                record.state = OID4VCIExchangeRecord.STATE_DELETED
            else:
                raise web.HTTPBadRequest(reason="invalid_notification_request")
            record.notification_event = {"event": event, "description": event_desc}
            await record.save(session, reason="Updated by notification")
        except (StorageError, BaseModelError, StorageNotFoundError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)
