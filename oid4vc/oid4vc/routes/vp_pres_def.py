"""Presentation definition routes for OID4VP admin API."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..models.presentation_definition import OID4VPPresDef, OID4VPPresDefSchema
from ..models.request import OID4VPRequest, OID4VPRequestSchema


class CreateOID4VPPresDefRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={
            "description": "The presentation definition",
        },
    )


class CreateOID4VPPresDefResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={"descripton": "The created presentation definition"},
    )

    pres_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP Presentation Definition.",
)
@request_schema(CreateOID4VPPresDefRequestSchema())
@response_schema(CreateOID4VPPresDefResponseSchema())
async def create_oid4vp_pres_def(request: web.Request):
    """Create an OID4VP Presentation Definition."""

    context: AdminRequestContext = request["context"]
    body = await request.json()

    async with context.session() as session:
        record = OID4VPPresDef(
            pres_def=body["pres_def"],
        )
        await record.save(session=session)

    return web.json_response(
        {
            "pres_def": record.serialize(),
            "pres_def_id": record.pres_def_id,
        }
    )


class PresDefIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation id."""

    pres_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


class UpdateOID4VPPresDefRequestSchema(OpenAPISchema):
    """Request schema for updating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={
            "description": "The presentation definition",
        },
    )


class UpdateOID4VPPresDefResponseSchema(OpenAPISchema):
    """Response schema for updating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={"descripton": "The updated presentation definition"},
    )

    pres_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Update an OID4VP Presentation Definition.",
)
@match_info_schema(PresDefIDMatchSchema())
@request_schema(UpdateOID4VPPresDefRequestSchema())
@response_schema(UpdateOID4VPPresDefResponseSchema())
async def update_oid4vp_pres_def(request: web.Request):
    """Update an OID4VP Presentation Request."""

    context: AdminRequestContext = request["context"]
    body = await request.json()
    pres_def_id = request.match_info["pres_def_id"]

    try:
        async with context.session() as session:
            record = await OID4VPPresDef.retrieve_by_id(session, pres_def_id)
            record.pres_def = body["pres_def"]
            await record.save(session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(
        {
            "pres_def": record.serialize(),
            "pres_def_id": record.pres_def_id,
        }
    )


class PresRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "Request identifier",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch presentation request.",
)
@match_info_schema(PresRequestIDMatchSchema())
@response_schema(OID4VPRequestSchema())
async def get_oid4vp_request_by_id(request: web.Request):
    """Request handler for retrieving a presentation request."""

    context: AdminRequestContext = request["context"]
    request_id = request.match_info["request_id"]

    try:
        async with context.session() as session:
            record = await OID4VPRequest.retrieve_by_id(session, request_id)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


class OID4VPPresDefQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )


class OID4VPPresDefListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresDefSchema(),
        many=True,
        metadata={"description": "Presentation Definitions"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all Presentation Definitions.",
)
@querystring_schema(OID4VPPresDefQuerySchema())
@response_schema(OID4VPPresDefListSchema())
async def list_oid4vp_pres_defs(request: web.Request):
    """Request handler for searching presentations."""

    context: AdminRequestContext = request["context"]

    try:
        if pres_def_id := request.query.get("pres_def_id"):
            async with context.profile.session() as session:
                record = await OID4VPPresDef.retrieve_by_id(session, pres_def_id)
                results = [record.serialize()]

        else:
            async with context.profile.session() as session:
                records = await OID4VPPresDef.query(session=session)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


@docs(
    tags=["oid4vp"],
    summary="Fetch presentation definition.",
)
@match_info_schema(PresDefIDMatchSchema())
@response_schema(OID4VPPresDefSchema())
async def get_oid4vp_pres_def_by_id(request: web.Request):
    """Request handler for retrieving a presentation definition."""

    context: AdminRequestContext = request["context"]
    pres_def_id = request.match_info["pres_def_id"]

    try:
        async with context.session() as session:
            record = await OID4VPPresDef.retrieve_by_id(session, pres_def_id)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=["oid4vp"],
    summary="Delete presentation definition.",
)
@match_info_schema(PresDefIDMatchSchema())
@response_schema(OID4VPPresDefSchema())
async def oid4vp_pres_def_remove(request: web.Request):
    """Request handler for removing a presentation definition."""

    context: AdminRequestContext = request["context"]
    pres_def_id = request.match_info["pres_def_id"]

    try:
        async with context.session() as session:
            record = await OID4VPPresDef.retrieve_by_id(session, pres_def_id)
            await record.delete_record(session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())
