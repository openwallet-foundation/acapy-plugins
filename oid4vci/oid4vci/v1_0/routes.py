"""Basic Messages Storage API Routes."""
import json
import logging
from typing import Mapping
import secrets
import string

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
)
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.protocols.basicmessage.v1_0.message_types import SPEC_URI
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from marshmallow import fields
from .models.cred_sup_record import OID4VCICredentialSupported
from .models.cred_ex_record import OID4VCICredentialExchangeRecord

LOGGER = logging.getLogger(__name__)
code_size = 8  # TODO: check


class CredExRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credential exchange record list query."""

    exchange_id = fields.UUID(
        required=False,
        metadata={"description": "exchange identifier"},
    )
    filter = fields.List(
        fields.Str(
            required=False,
            metadata={"description": "filters"},
        )
    )
    state = fields.Str(
        required=False,
        metadata={"description": "Credential exchange state"},
    )


class CreateCredExSchema(OpenAPISchema):
    credential_supported_id = fields.Str(
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


class CreateCredSupSchema(OpenAPISchema):
    credential_definition_id = fields.Str(
        required=True, metadata={"example": "UniversityDegree_JWT"}
    )
    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    types = fields.List(
        fields.Str(),
        metadata={"example": ["VerifiableCredential", "UniversityDegreeCredential"]},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": []}
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
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    credential_subject = fields.Dict(
        metadata={
            "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
            "family_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
            "degree": {},
            "gpa": {"display": [{"name": "GPA"}]},
        }
    )
    scope = fields.Str(
        required=True,
    )


class CredExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    cred_ex_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential exchange identifier",
        },
    )


class GetCredentialOfferSchema(OpenAPISchema):
    """Schema for GetCredential."""

    credentials = fields.List(fields.Str())
    credential_issuer = fields.Str()
    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential exchange records",
)
@querystring_schema(CredExRecordListQueryStringSchema)
async def credential_exchange_list(request: web.BaseRequest):
    """Request handler for searching credential exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request["context"]
    if exchange_id := request.query.get("exchange_id"):
        try:
            async with context.profile.session() as session:
                record = await OID4VCICredentialExchangeRecord.retrieve_by_id(
                    session=session, exchange_id=exchange_id
                )
            # There should only be one record for a id
            results = [record.serialize()]
        except (StorageError, BaseModelError, StorageNotFoundError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
    else:
        try:
            async with context.profile.session() as session:
                records = await OID4VCICredentialExchangeRecord.query(session=session)
            results = [record.serialize() for record in records]
        except (StorageError, BaseModelError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


@docs(
    tags=["oid4vci"],
    summary=("Create a credential exchange record"),
)
@request_schema(CreateCredExSchema())
async def credential_exchange_create(request: web.BaseRequest):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    context = request["context"]
    body = await request.json()
    credential_supported_id = body.get("credential_supported_id")
    credential_subject = body.get("credential_subject")
    # TODO: retrieve cred sup record and validate subjects
    nonce = body.get("nonce")
    pin = body.get("pin")
    token = body.get("token")

    # create exchange record from submitted
    record = OID4VCICredentialExchangeRecord(
        credential_supported_id=credential_supported_id,
        credential_subject=credential_subject,
        nonce=nonce,
        pin=pin,
        token=token,
    )
    async with context.session() as session:
        await record.save(session, reason="New oid4vci exchange")
    return web.json_response({"exchange_id": record.credential_exchange_id})


async def _create_free_offer(
    profile: Profile,
    filt_spec: Mapping = None,
    connection_id: str = None,
    auto_issue: bool = False,
    auto_remove: bool = False,
    replacement_id: str = None,
    preview_spec: dict = None,
    comment: str = None,
    trace_msg: bool = None,
):
    """Create a credential offer and related exchange record."""
    pass


@docs(
    tags=["oid4vci"],
    summary="Remove an existing credential exchange record",
)
@match_info_schema(CredExIdMatchInfoSchema())
async def credential_exchange_remove(request: web.BaseRequest):
    """Request handler for removing a credential exchange record.

    Args:
        request: aiohttp request object

    """
    pass


@docs(tags=["oid4vci"], summary="Get a credential offer")
@querystring_schema(GetCredentialOfferSchema())
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OIDC4VCI compliant offer, that
    can f.e. be used in QR-Code presented to a compliant wallet.
    """
    creds = request.query["credentials"]
    issuer_url = request.query["credential_issuer"]
    profile = request["context"].profile

    # TODO: check that the credential_issuer_url is associated with an issuer DID
    # TODO: check that the credential requested is offered by the issuer

    # Generate secure code
    code = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(code_size)
    )
    # Retrieve the exchange record
    oid4vci_ex_id = request.query["exchange_id"]

    try:
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            record: OID4VCICredentialExchangeRecord = await storage.find_record(
                OID4VCICredentialExchangeRecord.RECORD_TYPE,
                {OID4VCICredentialExchangeRecord.RECORD_ID_NAME: oid4vci_ex_id},
            )
        record.code = code
        # Save the code to the exchange record
        await record.save(session,  reason="New cred offer code")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    # Create offer object
    offer = {
        "credential_issuer": issuer_url,
        "credentials": creds,
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": False,  # TODO: put as a parameter
            }
        },
    }
    # Return it

    return web.json_response(offer)


@docs(tags=["oid4vci"], summary="Register a Oid4vci credential")
@request_schema(CreateCredSupSchema())
async def credential_supported_create(request: web.BaseRequest):
    context = request["context"]
    profile = context.profile

    body = await request.json()

    credential_definition_id = body.get("credential_definition_id")
    format = body.get("format")
    types = body.get("types")
    cryptographic_binding_methods_supported = body.get(
        "cryptographic_binding_methods_supported"
    )
    cryptographic_suites_supported = body.get("cryptographic_suites_supported")
    display = body.get("display")
    credential_subject = body.get("credential_subject")
    scope = body.get("scope")

    record = OID4VCICredentialSupported(
        credential_supported_id=credential_definition_id,
        format=format,
        types=types,
        cryptographic_binding_methods_supported=cryptographic_binding_methods_supported,
        cryptographic_suites_supported=cryptographic_suites_supported,
        display=display,
        credential_subject=credential_subject,
        scope=scope,
    )

    async with profile.session() as session:
        await record.save(session, reason="Save credential supported record.")

    return web.json_response(record.serialize())


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential supported records",
)
@querystring_schema(CredExRecordListQueryStringSchema)
async def credential_supported_list(request: web.BaseRequest):
    """Request handler for searching credential supported records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    pass


async def register(app: web.Application):
    """Register routes."""
    # add in the message list(s) route
    app.add_routes(
        [
            web.get("/oid4vci/credential-offer", get_cred_offer, allow_head=False),
            web.get(
                "/oid4vci/exchange/records",
                credential_exchange_list,
                allow_head=False,
            ),
            web.post("/oid4vci/exchange/create", credential_exchange_create),
            web.delete(
                "/oid4vci/exchange/records/{cred_ex_id}",
                credential_exchange_remove,
            ),
            web.post(
                "/oid4vci/credential-supported/create", credential_supported_create
            ),
            web.get(
                "/oid4vci/credential-supported/records",
                credential_supported_list,
                allow_head=False,
            ),
            web.delete(
                "/oid4vci/exchange-supported/records/{cred_sup_id}",
                credential_supported_list,
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
