"""Exchange record CRUD endpoints."""

import logging
import secrets
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    Uri,
)
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)
from acapy_agent.wallet.jwt import nym_to_did
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields
from marshmallow.validate import OneOf

from oid4vc.cred_processor import CredProcessors

from ..models.exchange import OID4VCIExchangeRecord, OID4VCIExchangeRecordSchema
from ..models.supported_cred import SupportedCredential

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
                record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
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


async def create_exchange(request: web.Request, refresh_id: str | None = None):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection.

    Args:
        request: aiohttp request object
        refresh_id: optional refresh identifier for the exchange record

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

    notification_id = secrets.token_urlsafe(CODE_BYTES)
    record = OID4VCIExchangeRecord(
        supported_cred_id=supported_cred_id,
        credential_subject=credential_subject,
        pin=pin,
        state=OID4VCIExchangeRecord.STATE_CREATED,
        verification_method=verification_method,
        issuer_id=issuer_id,
        refresh_id=refresh_id,
        notification_id=notification_id,
    )
    LOGGER.debug(f"Created exchange record: {record}")

    async with context.session() as session:
        await record.save(session, reason="New OpenID4VCI exchange")

    return record


@docs(
    tags=["oid4vci"],
    summary=("Create a credential exchange record"),
)
@request_schema(ExchangeRecordCreateRequestSchema())
@response_schema(OID4VCIExchangeRecordSchema())
@tenant_authentication
async def exchange_create(request: web.Request):
    """Request handler for creating a credential from attr values."""

    record = await create_exchange(request)
    return web.json_response(record.serialize())


class ExchangeRefreshIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    refresh_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential refresh identifier",
        },
    )


@docs(
    tags=["oid4vci"],
    summary=("Patch a credential exchange record"),
)
@match_info_schema(ExchangeRefreshIDMatchSchema())
@request_schema(ExchangeRecordCreateRequestSchema())
@response_schema(OID4VCIExchangeRecordSchema())
@tenant_authentication
async def credential_refresh(request: web.Request):
    """Request handler for creating a refresh credential from attr values."""
    context: AdminRequestContext = request["context"]
    refresh_id = request.match_info["refresh_id"]

    try:
        async with context.session() as session:
            try:
                existing = await OID4VCIExchangeRecord.retrieve_by_refresh_id(
                    session=session,
                    refresh_id=refresh_id,
                    for_update=True,
                )
                if existing:
                    if existing.state == OID4VCIExchangeRecord.STATE_OFFER_CREATED:
                        raise web.HTTPBadRequest(reason="Offer exists; cannot refresh.")
                    else:
                        existing.state = OID4VCIExchangeRecord.STATE_SUPERCEDED
                        await existing.save(session, reason="Superceded by new request.")
            except StorageNotFoundError:
                # we should allow refresh when all previous records were deleted
                pass
        record = await create_exchange(request, refresh_id)
        return web.json_response(record.serialize())

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err


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
    summary="Retrieve an exchange record by ID",
)
@match_info_schema(ExchangeRecordIDMatchSchema())
@response_schema(OID4VCIExchangeRecordSchema())
async def get_exchange_by_id(request: web.Request):
    """Request handler for retrieving an exchange record."""

    context: AdminRequestContext = request["context"]
    exchange_id = request.match_info["exchange_id"]

    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


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
