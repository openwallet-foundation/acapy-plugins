"""mso_mdoc admin routes."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.messaging.jsonld.error import (
    BadJWSHeaderError,
    InvalidVerificationMethod,
)
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from acapy_agent.resolver.base import ResolverError
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    request_schema,
    response_schema,
)
from marshmallow import RAISE, ValidationError, fields

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.supported_cred import SupportedCredential, SupportedCredentialSchema
from oid4vc.routes import SupportedCredentialMatchSchema, supported_cred_is_unique

from .mdoc import mso_mdoc_sign, mso_mdoc_verify

SPEC_URI = "https://www.iso.org/obp/ui/#iso:std:iso-iec:18013:-5:dis:ed-1:v1:en"
LOGGER = logging.getLogger(__name__)


class MdocSupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

    format = fields.Str(required=True, metadata={"example": "mso_mdoc"})
    identifier = fields.Str(
        data_key="id", required=True, metadata={"example": "DriverLicenceCredential"}
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": ["cose_key"]}
    )
    credential_signing_alg_values_supported = fields.List(
        fields.Str(), metadata={"example": ["-7", "-8"]}
    )
    proof_types_supported = fields.Dict(
        required=False,
        metadata={"example": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}},
    )
    doctype = fields.Str(
        required=True,
        metadata={
            "description": ("String designating the type of a Credential."),
            "example": "org.iso.18013.5.1.mDL",
        },
    )
    credential_metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Metadata about the credential, such as claims and display.",
            "example": {
                "claims": [
                    {
                        "path": ["org.iso.18013.5.1", "given_name"],
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    {
                        "path": ["org.iso.18013.5.1", "family_name"],
                        "display": [{"name": "Surname", "locale": "en-US"}],
                    },
                    {"path": ["org.iso.18013.5.1", "birth_date"], "mandatory": True},
                    {"path": ["org.iso.18013.5.1.aamva", "organ_donor"]},
                ],
                "display": [
                    {
                        "name": "Mobile Driving License",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://state.example.org/public/mdl.png",
                            "alt_text": "state mobile driving license",
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            },
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Register a configuration for a supported MSO mDoc credential",
)
@request_schema(MdocSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
@tenant_authentication
async def supported_credential_create_mdoc(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    assert isinstance(context, AdminRequestContext)
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    try:
        body: Dict[str, Any] = MdocSupportedCredCreateRequestSchema().load(
            body, unknown=RAISE
        )
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err

    if not await supported_cred_is_unique(body["identifier"], profile):
        raise web.HTTPBadRequest(
            reason=f"Record with identifier {body['identifier']} already exists."
        )

    LOGGER.info(f"body: {body}")

    vc_additional_data = {"doctype": body.pop("doctype", None)}
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


async def mdoc_supported_cred_update_helper(
    record: SupportedCredential,
    body: Dict[str, Any],
    session: AskarProfileSession,
) -> SupportedCredential:
    """Helper method for updating a MSO mDoc Supported Credential Record."""

    record.identifier = body.get("identifier", None)
    record.format = body.get("format", None)
    record.cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported", None
    )
    record.credential_signing_alg_values_supported = body.get(
        "credential_signing_alg_values_supported", None
    )
    record.proof_types_supported = body.get("proof_types_supported", None)
    record.credential_metadata = body.get("credential_metadata", None)
    record.vc_additional_data = {"doctype": body.get("doctype", None)}

    await record.save(session)
    return record


@docs(
    tags=["oid4vci"],
    summary="Update a Supported Credential. "
    "Expected to be a complete replacement of a MSO mDoc Supported Credential record, "
    "i.e., optional values that aren't supplied will be `None`, rather than retaining "
    "their original value.",
)
@match_info_schema(SupportedCredentialMatchSchema())
@request_schema(MdocSupportedCredCreateRequestSchema())
@response_schema(SupportedCredentialSchema())
async def update_supported_credential_mdoc(request: web.Request):
    """Update a MSO mDoc Supported Credential record."""

    context: AdminRequestContext = request["context"]
    supported_cred_id = request.match_info["supported_cred_id"]
    body: Dict[str, Any] = await request.json()
    try:
        body: Dict[str, Any] = MdocSupportedCredCreateRequestSchema().load(
            body, unknown=RAISE
        )
    except ValidationError as err:
        raise web.HTTPBadRequest(reason=str(err.messages)) from err

    LOGGER.info(f"body: {body}")

    try:
        async with context.session() as session:
            record = await SupportedCredential.retrieve_by_id(session, supported_cred_id)

            assert isinstance(session, AskarProfileSession)
            record = await mdoc_supported_cred_update_helper(record, body, session)

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


class MdocPluginResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc Plugin."""


class MdocCreateSchema(OpenAPISchema):
    """Request schema to create a jws with a particular DID."""

    headers = fields.Dict()
    payload = fields.Dict(required=True)
    did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={"description": "DID of interest", "example": GENERIC_DID_EXAMPLE},
    )
    verification_method = fields.Str(
        data_key="verificationMethod",
        required=False,
        validate=Uri(),
        metadata={
            "description": "Information used for proof verification",
            "example": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg34"
                "2Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )


class MdocVerifySchema(OpenAPISchema):
    """Request schema to verify a mso_mdoc."""

    mso_mdoc = fields.Str(
        validate=None, metadata={"example": "a36776657273696f6e63312e..."}
    )


class MdocVerifyResponseSchema(OpenAPISchema):
    """Response schema for mso_mdoc verification result."""

    valid = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    kid = fields.Str(required=True, metadata={"description": "kid of signer"})
    headers = fields.Dict(
        required=True, metadata={"description": "Headers from verified mso_mdoc."}
    )
    payload = fields.Dict(
        required=True, metadata={"description": "Payload from verified mso_mdoc"}
    )


@docs(
    tags=["mso_mdoc"],
    summary="Creates mso_mdoc CBOR encoded binaries according to ISO 18013-5",
)
@request_schema(MdocCreateSchema)
@response_schema(MdocPluginResponseSchema(), description="")
async def mdoc_sign(request: web.BaseRequest):
    """Request handler for sd-jws creation using did.

    Args:
        request: The web request object.

            "headers": { ... },
            "payload": { ... },
            "did": "did:example:123",
            "verificationMethod": "did:example:123#keys-1"
            with did and verification being mutually exclusive.

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    did = body.get("did")
    verification_method = body.get("verificationMethod")
    headers = body.get("headers", {})
    payload = body.get("payload", {})

    try:
        mso_mdoc = await mso_mdoc_sign(
            context.profile, headers, payload, did, verification_method
        )
    except ValueError as err:
        raise web.HTTPBadRequest(reason="Bad did or verification method") from err

    return web.json_response(mso_mdoc)


@docs(
    tags=["mso_mdoc"],
    summary="Verify mso_mdoc CBOR encoded binaries according to ISO 18013-5",
)
@request_schema(MdocVerifySchema())
@response_schema(MdocVerifyResponseSchema(), 200, description="")
async def mdoc_verify(request: web.BaseRequest):
    """Request handler for mso_mdoc validation.

    Args:
        request: The web request object.

            "mso_mdoc": { ... }
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    mso_mdoc = body["mso_mdoc"]
    try:
        result = await mso_mdoc_verify(context.profile, mso_mdoc)
    except (BadJWSHeaderError, InvalidVerificationMethod) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except ResolverError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post(
                "/oid4vci/credential-supported/create/mso-mdoc",
                supported_credential_create_mdoc,
            ),
            web.put(
                "/oid4vci/credential-supported/records/mso-mdoc/{supported_cred_id}",
                update_supported_credential_mdoc,
            ),
            web.post("/mso_mdoc/sign", mdoc_sign),
            web.post("/mso_mdoc/verify", mdoc_verify),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "mso_mdoc",
            "description": "mso_mdoc plugin",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
