"""SD-JWT VC extra routes."""

import logging
from typing import Any, Dict
from textwrap import dedent

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    request_schema,
    response_schema,
)
from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from marshmallow import fields


from oid4vc.cred_processor import CredProcessors

from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema
from oid4vc.routes import supported_cred_is_unique


LOGGER = logging.getLogger(__name__)


class SdJwtSupportedCredCreateReq(OpenAPISchema):
    """Schema for SdJwtSupportedCredCreateReq."""

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["did"]}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
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
    vct = fields.Str(
        required=True,
        metadata={
            "description": (
                "String designating the type of a Credential. This MAY be a "
                "URI but it can also be an arbitrary string value."
            ),
            "example": "https://example.com/id-card",
        },
    )
    order = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": (
                "The order in which claims should be displayed. This is not well defined "
                "by the spec right now. Best to omit for now."
            ),
        },
    )
    claims = fields.Dict(
        keys=fields.Str,
        required=False,
        metadata={
            "description": "Display information about claims.",
            "example": {
                "given_name": {
                    "display": [
                        {"name": "Given Name", "locale": "en-US"},
                        {"name": "Vorname", "locale": "de-DE"},
                    ]
                },
                "family_name": {
                    "display": [
                        {"name": "Surname", "locale": "en-US"},
                        {"name": "Nachname", "locale": "de-DE"},
                    ]
                },
                "email": {},
                "phone_number": {},
                "address": {
                    "street_address": {},
                    "locality": {},
                    "region": {},
                    "country": {},
                },
                "birthdate": {},
                "is_over_18": {},
                "is_over_21": {},
                "is_over_65": {},
            },
        },
    )
    sd_list = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "List of JSON pointers to selectively disclosable attributes.",
            "example": [
                "/given_name",
                "/family_name",
                "/email",
                "/phone_number",
                "/address",
                "/is_over_18",
                "/is_over_21",
                "/is_over_65",
            ],
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported SD-JWT VC credential",
    description=dedent("""
    This endpoint feeds into the Credential Issuer Metadata reported by the Issuer to its clients.

    See the SD-JWT VC profile for more details on these properties:
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-6
    """),  # noqa
)
@request_schema(SdJwtSupportedCredCreateReq())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()

    if not await supported_cred_is_unique(body["id"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['id']} already exists."
        )
    LOGGER.info(f"body: {body}")
    body["identifier"] = body.pop("id")
    format_data = {}
    format_data["vct"] = body.pop("vct")
    format_data["claims"] = body.pop("claims", None)
    format_data["order"] = body.pop("order", None)
    vc_additional_data = {}
    vc_additional_data["sd_list"] = body.pop("sd_list", None)

    record = SupportedCredential(
        **body,
        format_data=format_data,
        vc_additional_data=vc_additional_data,
    )

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with profile.session() as session:
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


class SupportedCredentialMatchSchema(OpenAPISchema):
    """Match info for request taking credential supported id."""

    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential supported identifier",
        },
    )


async def supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper method for updating a JWT Supported Credential Record."""
    format_data = {}
    vc_additional_data = {}

    body["identifier"] = body.pop("id")

    format_data["vct"] = body.pop("vct")
    format_data["claims"] = body.pop("claims", None)
    format_data["order"] = body.pop("order", None)
    vc_additional_data["sd_list"] = body.pop("sd_list", None)

    record.identifier = body["id"]
    record.format = body["format"]
    record.cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported", None
    )
    record.cryptographic_suites_supported = body.get(
        "cryptographic_suites_supported", None
    )
    record.display = body.get("display", None)
    record.format_data = format_data
    record.vc_additional_data = vc_additional_data

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a Supported Credential. "
    "Expected to be a complete replacement of an SD JWT Supported Credential record, "
    "i.e., optional values that aren't supplied will be `None`, rather than retaining "
    "their original value.",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(SdJwtSupportedCredCreateReq())
@response_schema(SupportedCredentialSchema())
async def update_supported_credential_sd_jwt(request: web.Request):
    """Update a JWT Supported Credential record."""

    context: AdminRequestContext = request["context"]
    body: Dict[str, Any] = await request.json()
    supported_cred_id = request.match_info["supported_cred_id"]

    LOGGER.info(f"body: {body}")
    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)

            assert isinstance(session, AskarProfileSession)
            record = await supported_cred_update_helper(record, body, session)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    registered_processors = context.inject(CredProcessors)
    if record.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {record.format} is not supported by"
            " currently registered processors"
        )

    processor = registered_processors.issuer_for_format(record.format)
    try:
        processor.validate_supported_credential(record)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(record.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/create/sd-jwt",
                supported_credential_create,
            ),
            web.put(
                "/oid4vci/credential-supported/records/sd-jwt/{supported_cred_id}",
                update_supported_credential_sd_jwt,
            ),
        ]
    )
