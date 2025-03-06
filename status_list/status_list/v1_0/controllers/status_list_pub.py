"""Status list publisher controller."""

import logging
import os
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.error import BaseError
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema
from marshmallow import fields
from marshmallow.validate import OneOf

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


class PublishStatusListSchema(OpenAPISchema):
    """Request schema for publishing status list."""

    did = fields.Str(
        required=False,
        metadata={
            "description": "did",
            "example": "did:web:dev.lab.di.gov.on.ca",
        },
    )
    verification_method = fields.Str(
        required=False,
        metadata={
            "description": "verification method",
            "example": "did:web:dev.lab.di.gov.on.ca#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",  # noqa: E501
        },
    )
    status_type = fields.Str(
        required=True,
        validate=OneOf(["w3c", "ietf"]),
        metadata={
            "description": "status type.",
            "example": "w3c",
        },
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
@request_schema(PublishStatusListSchema())
@response_schema(PublishStatusListResponseSchema(), 200, description="")
@tenant_authentication
async def publish_status_list(request: web.BaseRequest):
    """Request handler for publishing status list."""

    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"publishing status list with: {body}")

    definition_id = request.match_info["def_id"]

    issuer_did = body.get("did", None)
    verification_method = body.get("verification_method", None)
    if issuer_did is None and verification_method is None:
        raise web.HTTPBadRequest(reason="did or verification_method is required")

    status_type = body.get("status_type", None)
    if status_type is None:
        raise web.HTTPBadRequest(reason="status_type is required")

    try:
        published = []
        context: AdminRequestContext = request["context"]
        config = Config.from_settings(context.profile.settings)

        async with context.profile.session() as session:
            definition = await StatusListDef.retrieve_by_id(session, definition_id)

        for list_number in definition.list_numbers:
            status_list = await status_handler.get_status_list(
                context, definition, list_number, status_type, issuer_did
            )

            if status_type == "ietf":
                headers = {"typ": "statuslist+jwt"}
                payload = status_list

            elif status_type == "w3c":
                headers = {}
                payload = status_list

            jws = await jwt_sign(
                context.profile,
                headers,
                payload,
                did=issuer_did,
                verification_method=verification_method,
            )

            # publish status list
            wallet_id = status_handler.get_wallet_id(context)
            path = config.path_template.format(
                tenant_id=wallet_id,
                status_type=status_type,
                status_list_number=list_number,
            )
            if config.base_dir is not None:
                file_path = config.base_dir + path
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w") as file:
                    file.write(jws)

            published.append(payload)

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
