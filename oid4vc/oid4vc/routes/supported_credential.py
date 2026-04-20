"""Supported credential routes for OID4VCI admin API."""

from typing import Any, Dict

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
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

# Fields allowed in SupportedCredential constructor
_ALLOWED_SUPPORTED_CRED_FIELDS = {
    "format",
    "identifier",
    "cryptographic_binding_methods_supported",
    "credential_signing_alg_values_supported",
    "cryptographic_suites_supported",
    "proof_types_supported",
    "display",
    "credential_metadata",
    "format_data",
    "vc_additional_data",
}


def _move_fields_to_vc_additional_data(body: Dict[str, Any]) -> None:
    """Move top-level type/@context fields into vc_additional_data.

    Args:
        body: The request body (modified in-place)
    """
    vc_additional_data = body.get("vc_additional_data", {})
    for field in ["type", "@context"]:
        if field in body:
            vc_additional_data[field] = body.pop(field)
    if vc_additional_data:
        body["vc_additional_data"] = vc_additional_data


def _derive_jwt_vc_format_data(body: Dict[str, Any]) -> None:
    """Derive format_data for jwt_vc_json from vc_additional_data.

    Args:
        body: The request body (modified in-place)
    """
    if body.get("format") != "jwt_vc_json" or body.get("format_data"):
        return

    derived_format_data = {}
    if "vc_additional_data" in body:
        if "type" in body["vc_additional_data"]:
            derived_format_data["types"] = body["vc_additional_data"]["type"]
        if "@context" in body["vc_additional_data"]:
            derived_format_data["context"] = body["vc_additional_data"]["@context"]

    if "credentialSubject" in body:
        derived_format_data["credentialSubject"] = body.pop("credentialSubject")

    if derived_format_data:
        body["format_data"] = derived_format_data


def _ensure_jwt_vc_additional_data(body: Dict[str, Any]) -> None:
    """Ensure vc_additional_data has required fields for jwt_vc_json.

    Args:
        body: The request body (modified in-place)
    """
    if body.get("format") != "jwt_vc_json" or not body.get("format_data"):
        return

    format_data = body.get("format_data", {})
    if "vc_additional_data" not in body:
        body["vc_additional_data"] = {}

    vc_additional = body["vc_additional_data"]

    # Copy type/types from format_data if not already set
    if "type" not in vc_additional:
        if "type" in format_data:
            vc_additional["type"] = format_data["type"]
        elif "types" in format_data:
            vc_additional["type"] = format_data["types"]

    # Copy @context from format_data if not already set
    if "@context" not in vc_additional:
        if "context" in format_data:
            vc_additional["@context"] = format_data["context"]
        elif "@context" in format_data:
            vc_additional["@context"] = format_data["@context"]
        else:
            vc_additional["@context"] = ["https://www.w3.org/2018/credentials/v1"]


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
                # Only 'format' is indexed as a tag in SupportedCredential.TAG_NAMES.
                # Filtering by cryptographic_binding_methods_supported or
                # cryptographic_suites_supported would require post-query filtering
                # since they are list fields stored in record_value, not tags.
                filter_ = {
                    attr: value
                    for attr in ("format",)
                    if (value := request.query.get(attr))
                }
                records = await SupportedCredential.query(
                    session=session, tag_filter=filter_
                )
                results = [record.serialize() for record in records]
    except (StorageError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

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
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

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
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(record.serialize())
