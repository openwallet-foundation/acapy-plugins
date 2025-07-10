"""status list admin routes."""

import logging

from aiohttp import web

from .controllers.status_list_cred import (
    get_status_list_cred,
    update_status_list_cred,
    bind_status_list_cred,
)
from .controllers.status_list_def import (
    create_status_list_def,
    get_status_list_defs,
    get_status_list_def,
    update_status_list_def,
    delete_status_list_def,
)
from .controllers.status_list_shard import get_status_list, assign_status_list_entry
from .controllers.status_list_pub import publish_status_list


LOGGER = logging.getLogger(__name__)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            #
            # status list credentials
            #
            web.post(
                "/status-list/assign/{supported_cred_id}/creds/{cred_id}",
                bind_status_list_cred,
            ),
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
            web.patch(
                "/status-list/defs/{def_id}",
                update_status_list_def,
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
