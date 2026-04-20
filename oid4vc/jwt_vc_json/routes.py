"""JWT VC JSON extra routes."""

import logging
from typing import Any, Dict

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
from marshmallow import RAISE, ValidationError, fields

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema
from oid4vc.routes import SupportedCredentialMatchSchema, supported_cred_is_unique

LOGGER = logging.getLogger(__name__)


class JwtSupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for creating a JWT VC supported credential."""

    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "UniversityDegreeCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["did"]}
    )
    credential_signing_alg_values_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    credential_definition = fields.Dict(
        required=False,
        metadata={
            "example": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
            },
            "description": "Credential definition with type and context.",
        },
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={"example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}},
    )
    credential_metadata = fields.Dict(
        required=False,
        metadata={
            "example": {
                "display": [
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
                ],
                "claims": [
                    {
                        "path": ["given_name"],
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    {
                        "path": ["family_name"],
                        "display": [{"name": "Surname", "locale": "en-US"}],
                    },
                ],
            }
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported JWT VC credential",
)
@request_schema(JwtSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create_jwt(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    # Backward compat: accept top-level @context/type (old API) alongside
    # the OID4VCI 1.0 credential_definition wrapping.
    if "credential_definition" not in body:
        compat: Dict[str, Any] = {}
        for key in ("@context", "type", "credentialSubject", "order"):
            if key in body:
                compat[key] = body.pop(key)
        if compat:
            body["credential_definition"] = compat
    try:
        body = JwtSupportedCredCreateRequestSchema().load(body, unknown=RAISE)
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err

    if not await supported_cred_is_unique(body["identifier"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['identifier']} already exists."
        )

    LOGGER.debug(
        "Creating JWT VC supported credential from request payload: %s",
        body,
    )

    vc_additional_data = body.pop("credential_definition", None)
    record = SupportedCredential(**body, vc_additional_data=vc_additional_data)

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


async def jwt_supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper method for updating a JWT Supported Credential Record."""
    record.identifier = body["identifier"]
    record.format = body["format"]
    record.cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported", None
    )
    record.credential_signing_alg_values_supported = body.get(
        "credential_signing_alg_values_supported", None
    )
    record.vc_additional_data = body.get("credential_definition", None)
    record.proof_types_supported = body.get("proof_types_supported", None)
    record.credential_metadata = body.get("credential_metadata", None)

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a Supported Credential. "
    "Expected to be a complete replacement of a JWT Supported Credential record.",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(JwtSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
async def update_supported_credential_jwt_vc(request: web.Request):
    """Update a JWT Supported Credential record."""
    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]
    body: Dict[str, Any] = await request.json()
    if "credential_definition" not in body:
        compat: Dict[str, Any] = {}
        for key in ("@context", "type", "credentialSubject", "order"):
            if key in body:
                compat[key] = body.pop(key)
        if compat:
            body["credential_definition"] = compat
    try:
        body = JwtSupportedCredCreateRequestSchema().load(body, unknown=RAISE)
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err

    LOGGER.debug(
        "Updating JWT VC supported credential %s with request payload: %s",
        supported_cred_id,
        body,
    )

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)
            assert isinstance(session, AskarProfileSession)
            record = await jwt_supported_cred_update_helper(record, body, session)
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
                "/oid4vci/credential-supported/create/jwt",
                supported_credential_create_jwt,
            ),
            web.put(
                "/oid4vci/credential-supported/records/jwt/{supported_cred_id}",
                update_supported_credential_jwt_vc,
            ),
        ]
    )
