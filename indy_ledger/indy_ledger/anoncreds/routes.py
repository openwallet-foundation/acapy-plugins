"""AnonCreds revocation registry routes."""

import logging
import re

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.anoncreds.base import AnonCredsObjectNotFound, AnonCredsResolutionError
from acapy_agent.anoncreds.events import REV_LIST_UPDATE_FAILED_EVENT
from acapy_agent.anoncreds.routes.revocation import REVOCATION_TAG_TITLE
from acapy_agent.anoncreds.routes.revocation.registry import (
    AnonCredsRevRegIdMatchInfoSchema,
)
from acapy_agent.core.event_bus import EventBus, EventWithMetadata
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.utils.profiles import is_not_anoncreds_profile_raise_web_exception
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, response_schema
from marshmallow import fields

from .recover import fix_and_publish_from_invalid_accum_err
from .registry import LegacyIndyRegistry

LOGGER = logging.getLogger(__name__)


class CredRevIndyRecordsResultSchemaAnonCreds(OpenAPISchema):
    """Result schema for revoc reg delta."""

    rev_reg_delta = fields.Dict(
        metadata={"description": "Indy revocation registry delta"}
    )


@docs(
    tags=[REVOCATION_TAG_TITLE],
    summary="Get details of revoked credentials from ledger",
)
@match_info_schema(AnonCredsRevRegIdMatchInfoSchema())
@response_schema(CredRevIndyRecordsResultSchemaAnonCreds(), 200, description="")
@tenant_authentication
async def get_rev_reg_indy_recs(request: web.BaseRequest):
    """Request handler to get details of revoked credentials from ledger.

    Args:
        request: aiohttp request object

    Returns:
        Details of revoked credentials from ledger

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile

    is_not_anoncreds_profile_raise_web_exception(profile)

    rev_reg_id = request.match_info["rev_reg_id"]
    indy_registry = LegacyIndyRegistry()

    if await indy_registry.supports(rev_reg_id):
        try:
            rev_reg_delta, _ts = await indy_registry.get_revocation_registry_delta(
                profile, rev_reg_id, None
            )
        except (AnonCredsObjectNotFound, AnonCredsResolutionError) as e:
            raise web.HTTPInternalServerError(reason=str(e)) from e

        return web.json_response(
            {
                "rev_reg_delta": rev_reg_delta,
            }
        )

    raise web.HTTPInternalServerError(
        reason="Indy registry does not support revocation registry "
        f"identified by {rev_reg_id}"
    )
    
def register_events(event_bus: EventBus):
    """Subscribe to any events we need to support."""
    # If revocation list requires endorsement and fails to update, this event is emitted
    # to trigger retry logic and notify of failure
    event_bus.subscribe(
        re.compile(REV_LIST_UPDATE_FAILED_EVENT),
        notify_issuer_about_update_failure_due_to_endorsement,
    )


async def notify_issuer_about_update_failure_due_to_endorsement(
    profile: Profile,
    event: EventWithMetadata,
) -> None:
    """Notify issuer about a failure that couldn't be automatically recovered.

    Args:
        profile (Profile): The profile context
        event (EventWithMetadata): Failure message describing the endorsement failure

    """
    await fix_and_publish_from_invalid_accum_err(profile, event.payload["msg"])


async def register(app: web.Application) -> None:
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/anoncreds/revocation/registry/{rev_reg_id}/issued/indy_recs",
                get_rev_reg_indy_recs,
                allow_head=False,
            ),
        ]
    )


def post_process_routes(app: web.Application) -> None:
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": REVOCATION_TAG_TITLE,
            "description": "AnonCreds revocation registry management",
            "externalDocs": {
                "description": "Overview",
                "url": "https://github.com/hyperledger/indy-hipe/tree/master/text/0011-cred-revocation",
            },
        }
    )
