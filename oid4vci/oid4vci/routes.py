"""Basic Messages Storage API Routes."""
import logging
from os import getenv
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
from pydid import DIDUrl

from .models.exchange import OID4VCIExchangeRecord, OID4VCIExchangeRecordSchema
from .models.supported_cred import SupportedCredential

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
    nonce = (
        fields.Str(
            required=False,
        ),
    )
    pin = (
        fields.Str(
            required=False,
        ),
    )
    token = fields.Str(
        required=False,
    )


@docs(
    tags=["oid4vci"],
    summary=("Create a credential exchange record"),
)
@request_schema(ExchangeRecordCreateRequestSchema())
@response_schema(OID4VCIExchangeRecordSchema())
async def credential_exchange_create(request: web.BaseRequest):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()
    LOGGER.info(f"creating exchange with {body}")
    supported_cred_id = body.get("supported_cred_id")
    credential_subject = body.get("credential_subject")
    # TODO: retrieve cred sup record and validate subjects
    nonce = body.get("nonce")
    pin = body.get("pin")
    token = body.get("token")

    did = body.get("did")
    verification_method = body.get("verification_method")

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
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    # create exchange record from submitted
    record = OID4VCIExchangeRecord(
        supported_cred_id=supported_cred_id,
        credential_subject=credential_subject,
        verification_method=verification_method,
        nonce=nonce,
        pin=pin,
        token=token,
    )
    LOGGER.info(f"created exchange record {record}")

    async with context.session() as session:
        await record.save(session, reason="New oid4vci exchange")

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
    summary="Remove an existing credential exchange record",
)
@match_info_schema(ExchangeRecordIDMatchSchema())
async def credential_exchange_remove(request: web.BaseRequest):
    """Request handler for removing a credential exchange record.

    Args:
        request: aiohttp request object

    """
    pass


class CredOfferQuerySchema(OpenAPISchema):
    """Schema for GetCredential."""

    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


@docs(tags=["oid4vci"], summary="Get a credential offer")
@querystring_schema(CredOfferQuerySchema())
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OIDC4VCI compliant offer.

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    issuer_url = getenv("OID4VCI_ENDPOINT")
    user_pin_required = getenv("OID4VCI_USER_PIN_REQUIRED", False)
    oid4vci_ex_id = request.query.get("exchange_id")

    profile = request["context"].profile

    # TODO: check that the credential_issuer_url is associated with an issuer DID
    # TODO: check that the credential requested,
    # TODO:(this check should be done in exchange record creation) is offered
    # by the issuer

    # Generate secure code
    code = bytes_to_b64(secrets.token_bytes(CODE_BYTES), urlsafe=True, pad=False)

    try:
        async with profile.session() as session:
            record: OID4VCIExchangeRecord = await OID4VCIExchangeRecord.retrieve_by_id(
                session,
                record_id=oid4vci_ex_id,
            )
            record.code = code
            # Save the code to the exchange record
            await record.save(session, reason="New cred offer code")
            sup_record = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    # Create offer object
    offer = {
        "credential_issuer": issuer_url,
        "credentials": [sup_record.identifier],
        "grants": {
            # "authorization_code": {
            #    "issuer_state": 'previously-created-state',
            #    "authorization_server": ""
            # },
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": user_pin_required,
                # "interval": 30,
                # "authorization_server": ""
            }
        },
    }
    # Return it

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
async def credential_supported_create(request: web.Request):
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


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential supported records",
)
@querystring_schema(ExchangeRecordQuerySchema)
async def credential_supported_list(request: web.BaseRequest):
    """Request handler for searching credential supported records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request["context"]
    try:
        async with context.profile.session() as session:
            if exchange_id := request.query.get("id"):
                record = await SupportedCredential.retrieve_by_id(session, exchange_id)
                # There should only be one record for a id
                results = [record.serialize()]
            else:
                # TODO: use filter
                records = await SupportedCredential.query(session=session)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


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
            web.post("/oid4vci/exchange/create", credential_exchange_create),
            # web.delete(
            #    "/oid4vci/exchange/records/{exchange_id}",
            #    credential_exchange_remove,
            # ),
            web.post(
                "/oid4vci/credential-supported/create", credential_supported_create
            ),
            web.get(
                "/oid4vci/credential-supported/records",
                credential_supported_list,
                allow_head=False,
            ),
            # web.delete(
            #    "/oid4vci/exchange-supported/records/{cred_sup_id}",
            #    credential_supported_remove,
            # ),
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
