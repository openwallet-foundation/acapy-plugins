"""Basic Messages Storage API Routes."""
import logging
import secrets
from typing import Any, Dict

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)
from aries_cloudagent.wallet.jwt import nym_to_did
from aries_cloudagent.wallet.util import bytes_to_b64
from marshmallow import fields
from marshmallow.validate import OneOf

from .models.exchange import OID4VCIExchangeRecord, OID4VCIExchangeRecordSchema
from .models.supported_cred import SupportedCredential, SupportedCredentialSchema
from .config import Config

SPEC_URI = (
    "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html"
)
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
            if exchange_id := request.query.get("id"):
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
    credential_subject = (
        fields.Dict(
            required=True,
            metadata={
                "description": "desired claim and value in credential",
            },
        ),
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

    did = body.pop("did", None)
    verification_method = body.pop("verification_method", None)

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

    record = OID4VCIExchangeRecord(
        **body,
        state=OID4VCIExchangeRecord.STATE_CREATED,
        verification_method=verification_method,
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


@docs(tags=["oid4vci"], summary="Get a credential offer")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferSchema(), 200)
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer.

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    exchange_id = request.query["exchange_id"]

    code = bytes_to_b64(secrets.token_bytes(CODE_BYTES), urlsafe=True, pad=False)

    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )

            record.code = code
            await record.save(
                session, reason="Credential offer pre-authorized code created"
            )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    user_pin_required: bool = record.pin is not None
    offer = {
        "credential_issuer": config.endpoint,
        "credentials": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": user_pin_required,
            }
        },
    }

    return web.json_response(offer)


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
async def supported_credential_create(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    LOGGER.info(f"body: {body}")
    body["identifier"] = body.pop("id")

    record = SupportedCredential(
        **body,
    )

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


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get("/oid4vci/credential-offer", get_cred_offer, allow_head=False),
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
            web.get(
                "/oid4vci/credential-supported/records",
                supported_credential_list,
                allow_head=False,
            ),
            web.delete(
                "/oid4vci/exchange-supported/records/{cred_sup_id}",
                supported_credential_remove,
            ),
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
            "description": "oid4vci plugin",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
