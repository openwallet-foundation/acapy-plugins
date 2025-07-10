"""Status list publisher controller."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.error import BaseError
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, response_schema
from marshmallow import fields

from .. import status_handler
from ..config import Config
from ..jwt import jwt_sign
from ..models import StatusListDef

LOGGER = logging.getLogger(__name__)


class MatchStatusListDefRequest(OpenAPISchema):
    """Match info for request with identifier."""

    def_id = fields.Str(
        required=True,
        metadata={"description": "Status list definition identifier."},
    )


class PublishStatusListResponseSchema(OpenAPISchema):
    """Response schema for publishing status list."""

    published = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    definition_id = fields.Str(
        required=True, metadata={"description": "Status list definition id."}
    )
    status_lists = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "Published status lists."},
    )


@docs(
    tags=["status-list"],
    summary="Publish all status lists under a status list definition",
)
@match_info_schema(MatchStatusListDefRequest())
@response_schema(PublishStatusListResponseSchema(), 200, description="")
@tenant_authentication
async def publish_status_list(request: web.BaseRequest):
    """Request handler for publishing status list."""

    definition_id = request.match_info["def_id"]

    try:
        published = []
        context: AdminRequestContext = request["context"]
        config = Config.from_settings(context.profile.settings)
        wallet_id = status_handler.get_wallet_id(context)
        async with context.profile.session() as session:
            definition = await StatusListDef.retrieve_by_id(session, definition_id)

        for list_number in definition.list_numbers:
            status_list = await status_handler.get_status_list(
                context, definition, list_number
            )
            # publish status list
            if config.file_path is not None:
                path = config.file_path.format(
                    tenant_id=wallet_id,
                    list_number=list_number,
                )
                headers = (
                    {"typ": "statuslist+jwt"} if definition.list_type == "ietf" else {}
                )
                jws = await jwt_sign(
                    profile=context.profile,
                    headers=headers,
                    payload=status_list,
                    did=definition.issuer_did,
                    verification_method=definition.verification_method,
                )
                status_handler.write_to_file(path, jws.encode("utf-8"))
            # add status_list to published list
            published.append(status_list)

        return web.json_response(
            {
                "published": True,
                "definition_id": definition_id,
                "status_lists": published,
            }
        )

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except (StorageError, BaseModelError, BaseError) as err:
        raise web.HTTPInternalServerError(reason=err.roll_up) from err
