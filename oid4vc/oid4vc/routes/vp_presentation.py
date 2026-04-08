"""Presentation routes for OID4VP admin API."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    response_schema,
)
from marshmallow import fields
from marshmallow.validate import OneOf

from ..models.presentation import OID4VPPresentation, OID4VPPresentationSchema


class OID4VPPresQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    presentation_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by presentation identifier."},
    )
    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )
    state = fields.Str(
        required=False,
        validate=OneOf(OID4VPPresentation.STATES),
        metadata={"description": "Filter by presentation state."},
    )


class OID4VPPresListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresentationSchema(),
        many=True,
        metadata={"description": "Presentations"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all Presentations.",
)
@querystring_schema(OID4VPPresQuerySchema())
@response_schema(OID4VPPresListSchema())
async def list_oid4vp_presentations(request: web.Request):
    """Request handler for searching presentations."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if presentation_id := request.query.get("presentation_id"):
                record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("pres_def_id", "state")
                    if (value := request.query.get(attr))
                }
                records = await OID4VPPresentation.query(
                    session=session, tag_filter=filter_
                )
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


class PresentationIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation id."""

    presentation_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


class GetOID4VPPresResponseSchema(OpenAPISchema):
    """Request handler for returning a single presentation."""

    presentation_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )

    status = fields.Str(
        required=True,
        metadata={
            "description": "Status of the presentation",
        },
        validate=OneOf(
            [
                "request-created",
                "request-retrieved",
                "presentation-received",
                "presentation-invalid",
                "presentation-valid",
            ]
        ),
    )

    errors = fields.List(
        fields.Str(
            required=False,
            metadata={
                "description": "Errors raised during validation.",
            },
        )
    )

    verified_claims = fields.Dict(
        required=False,
        metadata={
            "description": "Any claims verified in the presentation.",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch presentation.",
)
@match_info_schema(PresentationIDMatchSchema())
@response_schema(GetOID4VPPresResponseSchema())
async def get_oid4vp_pres_by_id(request: web.Request):
    """Request handler for retrieving a presentation."""

    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    try:
        async with context.session() as session:
            record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=["oid4vp"],
    summary="Delete presentation.",
)
@match_info_schema(PresentationIDMatchSchema())
@response_schema(OID4VPPresentationSchema())
async def oid4vp_pres_remove(request: web.Request):
    """Request handler for removing a presentation."""

    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    try:
        async with context.session() as session:
            record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())
