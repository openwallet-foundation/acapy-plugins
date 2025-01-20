"""status list admin routes."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema

from .controllers import (
    # status list credentials
    get_status_list_cred,
    update_status_list_cred,
    # status list definitions
    create_status_list_def,
    get_status_list_defs,
    get_status_list_def,
    delete_status_list_def,
    # status list shards
    get_status_list,
    # status list entries
    assign_status_list_entry,
    # status list publisher
    publish_status_list,
    # development
    get_status_lists,
    get_status_list_entry,
    update_status_list_entry,
)

LOGGER = logging.getLogger(__name__)


class StatusListRequestSchema(OpenAPISchema):
    """Generic request schema for status list methods."""


class StatusListResponseSchema(OpenAPISchema):
    """Generic response schema for status list methods."""


@docs(
    tags=["status-list"],
    summary="generic statis list method",
)
@request_schema(StatusListRequestSchema())
@response_schema(StatusListResponseSchema(), 200, description="")
@tenant_authentication
async def status_list_generic_method(request: web.BaseRequest):
    """Request handler for generic method."""

    result = {"status": True}
    return web.json_response(result)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            #
            # status list credentials
            #
            web.get(
                "/status-list/defs/{def_id}/creds/{cred_id}",
                get_status_list_cred,
                allow_head=False,
            ),
            web.patch(
                "/status-list/defs/{def_id}/creds/{cred_id}",
                update_status_list_cred,
            ),
            #
            # status list definitions
            #
            web.post("/status-list/defs", create_status_list_def),
            web.get(
                "/status-list/defs",
                get_status_list_defs,
                allow_head=False,
            ),
            web.get(
                "/status-list/defs/{def_id}",
                get_status_list_def,
                allow_head=False,
            ),
            web.delete(
                "/status-list/defs/{def_id}",
                delete_status_list_def,
            ),
            #
            # status list entries
            #
            web.post(
                "/status-list/defs/{def_id}/entries",
                assign_status_list_entry,
            ),
            #
            # status list shards
            #
            web.get(
                "/status-list/defs/{def_id}/lists/{list_num}",
                get_status_list,
                allow_head=False,
            ),
            #
            # status list publish
            #
            web.put("/status-list/defs/{def_id}/publish", publish_status_list),
            #
            # status list dev
            #
            web.get(
                "/status-list/defs/{def_id}/lists",
                get_status_lists,
                allow_head=False,
            ),
            web.get(
                "/status-list/defs/{def_id}/lists/{list_num}/entries/{entry_idx}",
                get_status_list_entry,
                allow_head=False,
            ),
            web.patch(
                "/status-list/defs/{def_id}/lists/{list_num}/entries/{entry_idx}",
                update_status_list_entry,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "status-list",
            "description": "Status list operations",
            "externalDocs": {
                "description": "Specification",
                "url": (
                    "[https://www.w3.org/TR/vc-bitstring-status-list/]",
                    "[https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/]",
                ),
            },
        }
    )
