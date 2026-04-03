"""Supported credential CRUD endpoints."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
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

from ..models.supported_cred import SupportedCredential, SupportedCredentialSchema

LOGGER = logging.getLogger(__name__)


class SupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    doctype = fields.Str(required=False, metadata={"example": "org.iso.18013.5.1.mDL"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["did"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={"example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}},
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    format_data = fields.Dict(
        required=False,
        metadata={
            "description": (
                "Data specific to the credential format to be included in issuer "
                "metadata."
            ),
            "example": {
                "credentialSubject": {
                    "given_name": {
                        "display": [{"name": "Given Name", "locale": "en-US"}]
                    },
                    "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                    "degree": {},
                    "gpa": {"display": [{"name": "GPA"}]},
                },
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )
    vc_additional_data = fields.Dict(
        required=False,
        metadata={
            "description": (
                "Additional data to be included in each credential of this type. "
                "This is for data that is not specific to the subject but required "
                "by the credential format and is included in every credential."
            ),
            "example": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )


async def supported_cred_is_unique(identifier: str, profile: Profile):
    """Check whether a record exists with a given identifier."""

    async with profile.session() as session:
        records = await SupportedCredential.query(
            session, tag_filter={"identifier": identifier}
        )

    if len(records) > 0:
        return False
    return True


class SupportedCredentialQuerySchema(OpenAPISchema):
    """Query filters for credential supported record list query."""

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Filter by credential supported identifier."},
    )
    format = fields.Str(
        required=False,
        metadata={"description": "Filter by credential format."},
    )


class SupportedCredentialListSchema(OpenAPISchema):
    """Result schema for an credential supported record query."""

    results = fields.Nested(
        SupportedCredentialSchema(),
        many=True,
        metadata={"description": "Credential supported records"},
    )


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential supported records",
)
@querystring_schema(SupportedCredentialQuerySchema())
@response_schema(SupportedCredentialListSchema(), 200)
@tenant_authentication
async def supported_credential_list(request: web.BaseRequest):
    """Request handler for searching credential supported records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request["context"]
    try:
        async with context.profile.session() as session:
            if exchange_id := request.query.get("supported_cred_id"):
                record = await SupportedCredential.retrieve_by_id(session, exchange_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    # TODO filter by binding methods, suites?
                    for attr in ("format",)
                    if (value := request.query.get(attr))
                }
                records = await SupportedCredential.query(
                    session=session, tag_filter=filter_
                )
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


class SupportedCredentialMatchSchema(OpenAPISchema):
    """Match info for request taking credential supported id."""

    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential supported identifier",
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Get a credential supported record by ID",
)
@match_info_schema(SupportedCredentialMatchSchema())
@response_schema(SupportedCredentialSchema())
async def get_supported_credential_by_id(request: web.Request):
    """Request handler for retrieving an credential supported record by ID."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=["oid4vci"],
    summary="Remove an existing credential supported record",
)
@match_info_schema(SupportedCredentialMatchSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_remove(request: web.Request):
    """Request handler for removing an credential supported record."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())
