"""Admin API Routes."""

import json
import logging
import secrets
from typing import Any, Dict
from urllib.parse import quote

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.jwt import nym_to_did
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.util import bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_askar import Key, KeyAlg
from marshmallow import fields
from marshmallow.validate import OneOf

from oid4vc.cred_processor import CredProcessors
from oid4vc.jwk import DID_JWK, P256
from oid4vc.models.presentation import OID4VPPresentation, OID4VPPresentationSchema
from oid4vc.models.presentation_definition import OID4VPPresDef, OID4VPPresDefSchema
from oid4vc.models.request import OID4VPRequest, OID4VPRequestSchema

from .config import Config
from .models.exchange import OID4VCIExchangeRecord, OID4VCIExchangeRecordSchema
from .models.supported_cred import SupportedCredential, SupportedCredentialSchema

VCI_SPEC_URI = (
    "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html"
)
VP_SPEC_URI = "https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html"
LOGGER = logging.getLogger(__name__)
CODE_BYTES = 16


class ExchangeRecordQuerySchema(OpenAPISchema):
    """Parameters and validators for credential exchange record list query."""

    exchange_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by exchange record identifier."},
    )
    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Filter by supported credential identifier."},
    )
    state = fields.Str(
        required=False,
        validate=OneOf(OID4VCIExchangeRecord.STATES),
        metadata={"description": "Filter by exchange record state."},
    )


class ExchangeRecordListSchema(OpenAPISchema):
    """Result schema for an credential exchange record query."""

    results = fields.Nested(
        OID4VCIExchangeRecordSchema(),
        many=True,
        metadata={"description": "Exchange records"},
    )


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential exchange records",
)
@querystring_schema(ExchangeRecordQuerySchema())
@response_schema(ExchangeRecordListSchema(), 200)
@tenant_authentication
async def list_exchange_records(request: web.BaseRequest):
    """Request handler for searching exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The exchange record list

    """
    context = request["context"]
    try:
        async with context.profile.session() as session:
            if exchange_id := request.query.get("exchange_id"):
                record = await OID4VCIExchangeRecord.retrieve_by_id(
                    session, exchange_id
                )
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("supported_cred_id", "state")
                    if (value := request.query.get(attr))
                }
                records = await OID4VCIExchangeRecord.query(
                    session=session, tag_filter=filter_
                )
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


class ExchangeRecordCreateRequestSchema(OpenAPISchema):
    """Schema for ExchangeRecordCreateRequestSchema."""

    did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={"description": "DID of interest", "example": GENERIC_DID_EXAMPLE},
    )
    verification_method = fields.Str(
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
    supported_cred_id = fields.Str(
        required=True,
        metadata={
            "description": "Identifier used to identify credential supported record",
        },
    )
    credential_subject = fields.Dict(
        required=True,
        metadata={
            "description": "desired claim and value in credential",
        },
    )
    pin = fields.Str(
        required=False,
        metadata={
            "description": "User PIN sent out of band to the user.",
        },
    )


@docs(
    tags=["oid4vci"],
    summary=("Create a credential exchange record"),
)
@request_schema(ExchangeRecordCreateRequestSchema())
@response_schema(OID4VCIExchangeRecordSchema())
@tenant_authentication
async def exchange_create(request: web.Request):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    context: AdminRequestContext = request["context"]
    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"Creating OID4VCI exchange with: {body}")

    did = body.get("did", None)
    verification_method = body.get("verification_method", None)
    supported_cred_id = body["supported_cred_id"]
    credential_subject = body["credential_subject"]
    pin = body.get("pin")

    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = context.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, context.profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")

    if did:
        issuer_id = did
    else:
        issuer_id = verification_method.split("#")[0]

    async with context.session() as session:
        try:
            supported = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )
        except StorageNotFoundError:
            raise web.HTTPNotFound(
                reason=f"Supported cred identified by {supported_cred_id} not found"
            )

    registered_processors = context.inject(CredProcessors)
    if supported.format not in registered_processors.issuers:
        raise web.HTTPBadRequest(
            reason=f"Format {supported.format} is not supported by"
            " currently registered processors"
        )
    processor = registered_processors.issuer_for_format(supported.format)
    try:
        processor.validate_credential_subject(supported, credential_subject)
    except ValueError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    record = OID4VCIExchangeRecord(
        supported_cred_id=supported_cred_id,
        credential_subject=credential_subject,
        pin=pin,
        state=OID4VCIExchangeRecord.STATE_CREATED,
        verification_method=verification_method,
        issuer_id=issuer_id,
    )
    LOGGER.debug(f"Created exchange record: {record}")

    async with context.session() as session:
        await record.save(session, reason="New OpenID4VCI exchange")

    return web.json_response(record.serialize())


class ExchangeRecordIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    exchange_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential exchange identifier",
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Remove an existing exchange record",
)
@match_info_schema(ExchangeRecordIDMatchSchema())
@response_schema(OID4VCIExchangeRecordSchema())
@tenant_authentication
async def exchange_delete(request: web.Request):
    """Request handler for removing an exchange record."""

    context: AdminRequestContext = request["context"]
    exchange_id = request.match_info["exchange_id"]

    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


class CredOfferQuerySchema(OpenAPISchema):
    """Schema for GetCredential."""

    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


class CredOfferGrantSchema(OpenAPISchema):
    """Schema for GetCredential."""

    pre_authorized_code = fields.Str(required=True)
    user_pin_required = fields.Bool(required=False)


class CredOfferSchema(OpenAPISchema):
    """Credential Offer Schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential issuer.",
            "example": "https://example.com",
        },
    )
    credentials = fields.List(
        fields.Str(
            required=True,
            metadata={
                "description": "The credential type identifier.",
                "example": "UniversityDegreeCredential",
            },
        )
    )
    grants = fields.Nested(CredOfferGrantSchema(), required=True)


class CredOfferResponseSchemaVal(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential value for display by QR code.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)

class CredOfferResponseSchemaRef(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer_uri = fields.Str(
        required=True,
        metadata={
            "description": "A URL which references the credential for display.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)

async def _parse_cred_offer(context: AdminRequestContext, exchange_id: str) -> dict:
    """Helper function for cred_offer request parsing.
    
    Used in get_cred_offer and public_routes.dereference_cred_offer endpoints.
    """
    config = Config.from_settings(context.settings)
    code = secrets.token_urlsafe(CODE_BYTES)

    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )

            record.code = code
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    user_pin_required: bool = record.pin is not None
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credentials": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": user_pin_required,
            }
        },
    }

@docs(tags=["oid4vci"], summary="Get a credential offer by value")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
@tenant_authentication
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by value.

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    offer_uri = quote(json.dumps(offer))
    offer_response = {
        "offer": offer,
        "credential_offer": f"openid-credential-offer://?credential_offer={offer_uri}"
    }
    return web.json_response(offer_response)

@docs(tags=["oid4vci"], summary="Get a credential offer by reference")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaRef(), 200)
@tenant_authentication
async def get_cred_offer_by_ref(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by reference.
    
    credential_offer_uri can be dereferenced at the /oid4vc/dereference-credential-offer 
    (see public_routes.dereference_cred_offer)

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )

    offer = await _parse_cred_offer(context, exchange_id)

    config = Config.from_settings(context.settings)
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    ref_uri = f"{config.endpoint}{subpath}/oid4vci/dereference-credential-offer"
    offer_response = {
        "offer": offer,
        "credential_offer_uri": f"openid-credential-offer://?credential_offer={quote(ref_uri)}"
    }
    return web.json_response(offer_response)

class SupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

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
                "types": ["VerifiableCredential", "UniversityDegreeCredential"],
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


@docs(tags=["oid4vci"], summary="Register a Oid4vci credential")
@request_schema(SupportedCredCreateRequestSchema())
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

    record = SupportedCredential(
        **body,
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


class JwtSupportedCredCreateRequestSchema(OpenAPISchema):
    """Schema for SupportedCredCreateRequestSchema."""

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
    type = fields.List(
        fields.Str,
        required=True,
        metadata={
            "description": "List of credential types supported.",
            "example": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    credential_subject = fields.Dict(
        keys=fields.Str,
        data_key="credentialSubject",
        required=False,
        metadata={
            "description": "Metadata about the Credential Subject to help with display.",
            "example": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                "last_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
                "degree": {},
                "gpa": {"display": [{"name": "GPA"}]},
            },
        },
    )
    order = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": (
                "The order in which claims should be displayed. This is not well defined "
                "by the spec right now. Best to omit for now."
            )
        },
    )
    context = fields.List(
        fields.Raw,
        data_key="@context",
        required=True,
        metadata={
            "example": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
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
    LOGGER.info(f"body: {body}")
    body["identifier"] = body.pop("id")
    format_data = {}
    format_data["types"] = body.pop("type")
    format_data["credential_subject"] = body.pop("credentialSubject", None)
    format_data["context"] = body.pop("@context")
    format_data["order"] = body.pop("order", None)
    vc_additional_data = {}
    vc_additional_data["@context"] = format_data["context"]
    # type vs types is deliberate; OID4VCI spec is inconsistent with VCDM
    vc_additional_data["type"] = format_data["types"]

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
            record = await SupportedCredential.retrieve_by_id(
                session, supported_cred_id
            )
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


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
        req_record = OID4VPRequest(
            pres_def_id=body["pres_def_id"], vp_formats=body["vp_formats"]
        )
        await req_record.save(session=session)

        pres_record = OID4VPPresentation(
            pres_def_id=body["pres_def_id"],
            state=OID4VPPresentation.REQUEST_CREATED,
            request_id=req_record.request_id,
        )
        await pres_record.save(session=session)

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


class CreateOID4VPPresDefResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={"descripton": "The created presentation definition"},
    )


class CreateOID4VPPresDefRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP PresDef."""

    pres_def = fields.Dict(
        required=True,
        metadata={
            "description": "The presentation definition",
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
                record = await OID4VPPresentation.retrieve_by_id(
                    session, presentation_id
                )
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
@response_schema(OID4VPPresDefListSchema())
async def list_oid4vp_pres_defs(request: web.Request):
    """Request handler for searching presentations."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            records = await OID4VPPresDef.query(session=session)
            results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


class PresDefIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation id."""

    pres_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Presentation identifier",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch presentation.",
)
@match_info_schema(PresDefIDMatchSchema())
@response_schema(OID4VPPresDefSchema())
async def get_oid4vp_pres_def_by_id(request: web.Request):
    """Request handler for retrieving a presentation."""

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
    summary="Fetch presentation.",
)
@match_info_schema(PresDefIDMatchSchema())
@response_schema(OID4VPPresDefSchema())
async def oid4vp_pres_def_remove(request: web.Request):
    """Request handler for retrieving a presentation."""

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


class CreateDIDJWKRequestSchema(OpenAPISchema):
    """Request schema for creating a did:jwk."""

    key_type = fields.Str(
        required=True,
        metadata={
            "description": "Type of key",
        },
        validate=OneOf(
            [
                "ed25519",
                "p256",
            ]
        ),
    )


class CreateDIDJWKResponseSchema(OpenAPISchema):
    """Response schema for creating a did:jwk."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "The created did:jwk",
        },
    )


@docs(
    tags=["did"],
    summary="Create DID JWK.",
)
@request_schema(CreateDIDJWKRequestSchema())
@response_schema(CreateDIDJWKResponseSchema())
async def create_did_jwk(request: web.Request):
    """Route for creating a did:jwk."""

    context: AdminRequestContext = request["context"]
    body = await request.json()
    key_type = body["key_type"]
    key_types = context.inject(KeyTypes)

    async with context.session() as session:
        wallet = session.inject(BaseWallet)
        key_type_instance = key_types.from_key_type(key_type)

        if not key_type_instance:
            raise web.HTTPBadRequest(reason="Invalid key type")

        assert isinstance(session, AskarProfileSession)
        key = Key.generate(KeyAlg(key_type_instance.key_type))

        await session.handle.insert_key(
            key.get_jwk_thumbprint(),
            key,
        )
        jwk = json.loads(key.get_jwk_public())
        jwk["use"] = "sig"

        did = "did:jwk:" + bytes_to_b64(
            json.dumps(jwk).encode(), urlsafe=True, pad=False
        )

        did_info = DIDInfo(
            did=did,
            verkey=key.get_jwk_thumbprint(),
            metadata={},
            method=DID_JWK,
            key_type=P256,
        )

        await wallet.store_did(did_info)

        return web.json_response({"did": did})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get("/oid4vci/credential-offer", get_cred_offer, allow_head=False),
            web.get(
                "/oid4vci/credential-offer-by-ref",
                get_cred_offer_by_ref,
                allow_head=False
            ),
            web.get(
                "/oid4vci/exchange/records",
                list_exchange_records,
                allow_head=False,
            ),
            web.post("/oid4vci/exchange/create", exchange_create),
            web.delete("/oid4vci/exchange/records/{exchange_id}", exchange_delete),
            web.post(
                "/oid4vci/credential-supported/create", supported_credential_create
            ),
            web.post(
                "/oid4vci/credential-supported/create/jwt",
                supported_credential_create_jwt,
            ),
            web.get(
                "/oid4vci/credential-supported/records",
                supported_credential_list,
                allow_head=False,
            ),
            web.delete(
                "/oid4vci/exchange-supported/records/{supported_cred_id}",
                supported_credential_remove,
            ),
            web.post("/oid4vp/request", create_oid4vp_request),
            web.post("/oid4vp/presentation-definition", create_oid4vp_pres_def),
            web.get("/oid4vp/presentation-definitions", list_oid4vp_pres_defs),
            web.get(
                "/oid4vp/presentation-definition/{pres_def_id}",
                get_oid4vp_pres_def_by_id,
            ),
            web.delete(
                "/oid4vp/presentation-definition/{pres_def_id}", oid4vp_pres_def_remove
            ),
            web.get("/oid4vp/presentations", list_oid4vp_presentations),
            web.get("/oid4vp/presentation/{request_id}", get_oid4vp_pres_by_id),
            web.delete("/oid4vp/presentation/{presentation_id}", oid4vp_pres_remove),
            web.post("/did/jwk/create", create_did_jwk),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "oid4vci",
            "description": "OpenID for VC Issuance",
            "externalDocs": {"description": "Specification", "url": VCI_SPEC_URI},
        }
    )
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "oid4vp",
            "description": "OpenID for VP",
            "externalDocs": {"description": "Specification", "url": VP_SPEC_URI},
        }
    )
