"""DCQL query routes for OID4VP admin API."""

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

from ..models.dcql_query import (
    CredentialQuery,
    CredentialQuerySchema,
    CredentialSetQuerySchema,
    DCQLQuery,
    DCQLQuerySchema,
)


class CreateDCQLQueryRequestSchema(OpenAPISchema):
    """Request schema for creating a DCQL Query."""

    credentials = fields.List(
        fields.Nested(CredentialQuerySchema),
        required=True,
        metadata={"description": "A list of Credential Queries."},
    )

    credential_sets = fields.List(
        fields.Nested(CredentialSetQuerySchema),
        required=False,
        metadata={"description": "A list of Credential Set Queries."},
    )


class CreateDCQLQueryResponseSchema(OpenAPISchema):
    """Response schema from creating a DCQL Query."""

    dcql_query = fields.Dict(
        required=True,
        metadata={
            "description": "The DCQL query.",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create a DCQL Query record.",
)
@request_schema(CreateDCQLQueryRequestSchema())
@response_schema(CreateDCQLQueryResponseSchema())
async def create_dcql_query(request: web.Request):
    """Create a DCQL Query Record."""

    body = await request.json()
    context: AdminRequestContext = request["context"]

    credentials = body["credentials"]
    credential_sets = body.get("credential_sets")

    async with context.session() as session:
        cred_queries = []
        for cred in credentials:
            cred_queries.append(CredentialQuery.deserialize(cred))

        dcql_query = DCQLQuery(credentials=cred_queries, credential_sets=credential_sets)
        await dcql_query.save(session=session)

    return web.json_response(
        {
            "dcql_query": dcql_query.serialize(),
            "dcql_query_id": dcql_query.dcql_query_id,
        }
    )


class DCQLQueriesQuerySchema(OpenAPISchema):
    """Parameters and validators for DCQL Query List query."""

    dcql_query_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation identifier."},
    )


class DCQLQueryListSchema(OpenAPISchema):
    """Result schema for an DCQL Query List query."""

    results = fields.Nested(
        DCQLQuerySchema(),
        many=True,
        metadata={"description": "Presentations"},
    )


@docs(
    tags=["oid4vp"],
    summary="List all DCQL Query records.",
)
@querystring_schema(DCQLQueriesQuerySchema())
@response_schema(DCQLQueryListSchema())
async def list_dcql_queries(request: web.Request):
    """List all DCQL Query Records."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if dcql_query_id := request.query.get("dcql_query_id"):
                record = await DCQLQuery.retrieve_by_id(session, dcql_query_id)
                results = [record.serialize()]
            else:
                records = await DCQLQuery.query(session=session)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


class DCQLQueryIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation id."""

    dcql_query_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


class GetDCQLQueryResponseSchema(OpenAPISchema):
    """Request handler for returning a single DCQL Query."""

    dcql_query_id = fields.Str(
        required=True,
        metadata={
            "description": "Query identifier",
        },
    )

    credentials = fields.List(
        fields.Nested(CredentialQuerySchema),
        required=True,
        metadata={
            "description": "A list of credential query objects",
        },
    )

    credential_sets = fields.List(
        fields.Nested(CredentialSetQuerySchema),
        required=False,
        metadata={
            "description": "A list of credential set query objects",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch DCQL query.",
)
@match_info_schema(DCQLQueryIDMatchSchema())
@response_schema(GetDCQLQueryResponseSchema())
async def get_dcql_query_by_id(request: web.Request):
    """Request handler for retrieving a DCQL query."""

    context: AdminRequestContext = request["context"]
    dcql_query_id = request.match_info["dcql_query_id"]

    try:
        async with context.session() as session:
            record = await DCQLQuery.retrieve_by_id(session, dcql_query_id)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=["oid4vp"],
    summary="Delete DCQL Query.",
)
@match_info_schema(DCQLQueryIDMatchSchema())
@response_schema(DCQLQuerySchema())
async def dcql_query_remove(request: web.Request):
    """Request handler for removing a DCQL Query."""

    context: AdminRequestContext = request["context"]
    dcql_query_id = request.match_info["dcql_query_id"]

    try:
        async with context.session() as session:
            record = await DCQLQuery.retrieve_by_id(session, dcql_query_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())
