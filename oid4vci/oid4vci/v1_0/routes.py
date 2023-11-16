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
)
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.protocols.basicmessage.v1_0.message_types import SPEC_URI
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.wallet.util import bytes_to_b64
from marshmallow import INCLUDE, fields
from .models.supported_cred import SupportedCredential
from .models.exchange import OID4VCIExchangeRecord

LOGGER = logging.getLogger(__name__)
code_size = 8  # TODO: check


class CredExRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credential exchange record list query."""

    id = fields.UUID(
        required=False,
        metadata={"description": "identifier"},
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
    """Schema for CreateCredExSchema."""

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


class CreateCredSupSchema(OpenAPISchema):
    """Schema for CreateCredSupSchema."""

    class Meta:
        """CreateCredSupSchema metadata."""

        unknown = INCLUDE

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
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
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
    try:
        async with context.profile.session() as session:
            if exchange_id := request.query.get("id"):
                record = await OID4VCIExchangeRecord.retrieve_by_id(
                    session, exchange_id
                )
                # There should only be one record for a id
                results = [record.serialize()]
            else:
                # TODO: use filter
                records = await OID4VCIExchangeRecord.query(session=session)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
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
    LOGGER.info(f"creating exchange with {body}")
    supported_cred_id = body.get("supported_cred_id")
    credential_subject = body.get("credential_subject")
    # TODO: retrieve cred sup record and validate subjects
    nonce = body.get("nonce")
    pin = body.get("pin")
    token = body.get("token")

    # create exchange record from submitted
    record = OID4VCIExchangeRecord(
        supported_cred_id=supported_cred_id,
        credential_subject=credential_subject,
        nonce=nonce,
        pin=pin,
        token=token,
    )
    LOGGER.info(f"created exchange record {record}")

    async with context.session() as session:
        await record.save(session, reason="New oid4vci exchange")
    return web.json_response({"exchange_id": record.exchange_id})


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
    code = bytes_to_b64(secrets.token_bytes(code_size), urlsafe=True, pad=False)

    try:
        async with profile.session() as session:
            record: OID4VCIExchangeRecord = await OID4VCIExchangeRecord.retrieve_by_id(
                session,
                record_id=oid4vci_ex_id,
            )
            record.code = code
            # Save the code to the exchange record
            await record.save(session, reason="New cred offer code")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    # Create offer object
    offer = {
        "credential_issuer": issuer_url,
        "credentials": [record.supported_cred_id],
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


@docs(tags=["oid4vci"], summary="Register a Oid4vci credential")
@request_schema(CreateCredSupSchema())
async def credential_supported_create(request: web.Request):
    """Request handler for creating a credential supported record."""
    context = request["context"]
    profile = context.profile

    body: Dict[str, Any] = await request.json()
    LOGGER.info(f"body: {body}")
    known = {
        k: body.pop(k)
        for k in (
            "format",
            "identifier",
            "cryptographic_binding_methods_supported",
            "cryptographic_suites_supported",
            "display",
        )
        if k in body
    }
    format_specific = body
    LOGGER.info(f"format_data: {format_specific}")
    LOGGER.info(f"known: {known}")

    record = SupportedCredential(
        **known,
        format_data=format_specific,
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
    # add in the message list(s) route
    app.add_routes(
        [
            web.get(
                "/oid4vci/draft-11/credential-offer", get_cred_offer, allow_head=False
            ),
            web.get(
                "/oid4vci/draft-13/credential-offer", get_cred_offer, allow_head=False
            ),
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
