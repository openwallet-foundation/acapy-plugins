"""OID4VP request creation and listing endpoints."""

import logging
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from oid4vc.models.presentation import OID4VPPresentation, OID4VPPresentationSchema
from oid4vc.models.request import OID4VPRequest, OID4VPRequestSchema

from ..config import Config

LOGGER = logging.getLogger(__name__)


class CreateOID4VPReqResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP Request."""

    request_uri = fields.Str(
        required=True,
        metadata={
            "description": "URI for the holder to resolve the request",
        },
    )

    request = fields.Nested(
        OID4VPRequestSchema,
        required=True,
        metadata={"descripton": "The created request"},
    )

    presentation = fields.Nested(
        OID4VPPresentationSchema,
        required=True,
        metadata={"descripton": "The created presentation"},
    )


class CreateOID4VPReqRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP Request."""

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation definition",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify DCQL query",
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": "Expected presentation formats from the holder",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP Request.",
)
@request_schema(CreateOID4VPReqRequestSchema)
@response_schema(CreateOID4VPReqResponseSchema)
async def create_oid4vp_request(request: web.Request):
    """Create an OID4VP Request."""

    context: AdminRequestContext = request["context"]
    body = await request.json()

    async with context.session() as session:
        if pres_def_id := body.get("pres_def_id"):
            req_record = OID4VPRequest(
                pres_def_id=pres_def_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                pres_def_id=pres_def_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
            )
            await pres_record.save(session=session)

        elif dcql_query_id := body.get("dcql_query_id"):
            req_record = OID4VPRequest(
                dcql_query_id=dcql_query_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)
        else:
            raise web.HTTPBadRequest(
                reason="One of pres_def_id or dcql_query_id must be provided"
            )

    config = Config.from_settings(context.settings)
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    request_uri = quote(f"{config.endpoint}{subpath}/oid4vp/request/{req_record._id}")
    full_uri = f"openid://?request_uri={request_uri}"

    return web.json_response(
        {
            "request_uri": full_uri,
            "request": req_record.serialize(),
            "presentation": pres_record.serialize(),
        }
    )


class OID4VPRequestQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    request_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by request identifier."},
    )
    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )
    dcql_query_id = fields.Str(
        required=False,
        metadata={"description": "Filter by DCQL query identifier."},
    )


class OID4VPRequestListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresentationSchema(),
        many=True,
        metadata={"description": "Presentation Requests"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all OID4VP Requests.",
)
@querystring_schema(OID4VPRequestQuerySchema())
@response_schema(OID4VPRequestListSchema())
async def list_oid4vp_requests(request: web.Request):
    """Request handler for searching requests."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if request_id := request.query.get("request_id"):
                record = await OID4VPRequest.retrieve_by_id(session, request_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("pres_def_id", "dcql_query_id")
                    if (value := request.query.get(attr))
                }
                records = await OID4VPRequest.query(session=session, tag_filter=filter_)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})
