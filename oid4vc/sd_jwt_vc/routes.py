"""SD-JWT VC extra routes."""

import logging
from typing import Any, Dict
from textwrap import dedent

from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
)
from aries_cloudagent.admin.decorators.auth import tenant_authentication
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from marshmallow import fields


from oid4vc.cred_processor import CredProcessors

from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema


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
            ]
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported SD-JWT VC credential",
    description=dedent("""
    This endpoint feeds into the Credential Issuer Metadata reported by the Issuer to its clients.

    See the SD-JWT VC profile for more details on these properties:
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-6
    """), # noqa
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


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/create/sd-jwt", supported_credential_create
            ),
        ]
    )
