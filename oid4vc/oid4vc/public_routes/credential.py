"""Credential issuance endpoint."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
)
from marshmallow import fields

from .token import check_token, handle_proof_of_posession
from ..cred_processor import CredProcessors
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential

LOGGER = logging.getLogger(__name__)


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema for the /credential endpoint."""

    credential_configuration_id = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )
    type = fields.List(
        fields.Str(),
        metadata={"description": ""},
    )
    proofs = fields.Dict(metadata={"description": ""})


@docs(tags=["oid4vc"], summary="Issue a credential")
@request_schema(IssueCredentialRequestSchema())
async def issue_cred(request: web.Request):
    """The Credential Endpoint issues a Credential.

    As validated upon presentation of a valid Access Token.
    """
    context: AdminRequestContext = request["context"]
    token_result = await check_token(context, request.headers.get("Authorization"))
    refresh_id = token_result.payload["sub"]
    body = await request.json()
    LOGGER.info(f"request: {body}")
    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_refresh_id(
                session, refresh_id=refresh_id
            )
            if not ex_record:
                raise StorageNotFoundError("No exchange record found")
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason="No credential offer available.") from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not supported.format:
        raise web.HTTPBadRequest(reason="SupportedCredential missing format identifier.")

    # if supported.format != body.get("format"):
    #     raise web.HTTPBadRequest(reason="Requested format does not match offer.")

    authorization_details = token_result.payload.get("authorization_details", None)
    if authorization_details:
        found = any(
            isinstance(ad, dict)
            and ad.get("credential_configuration_id") == supported.identifier
            for ad in authorization_details
        )
        if not found:
            raise web.HTTPBadRequest(
                reason=f"{supported.identifier} is not authorized by the token."
            )

    c_nonce = token_result.payload.get("c_nonce") or ex_record.nonce
    if c_nonce is None:
        raise web.HTTPBadRequest(
            reason="Invalid exchange; no offer created for this request"
        )
    # TEMP UNDOING LOGIC FOR format_data
    #    if supported.format_data is None:
    #        LOGGER.error(f"No format_data for supported credential {supported.format}.")
    #        raise web.HTTPInternalServerError()
    LOGGER.debug(f"Supported credential format_data: {supported.format_data}")

    if "proofs" not in body:
        raise web.HTTPBadRequest(reason=f"proof is required for {supported.format}")

    pop = await handle_proof_of_posession(context.profile, body["proofs"], c_nonce)

    if not pop.verified:
        raise web.HTTPBadRequest(reason="Invalid proof")

    # try:
    processors = context.inject(CredProcessors)
    processor = processors.issuer_for_format(supported.format)

    credential = await processor.issue(body, supported, ex_record, pop, context)
    # except CredProcessorError as e:
    #     raise web.HTTPBadRequest(reason=e.message)

    async with context.session() as session:
        ex_record.state = OID4VCIExchangeRecord.STATE_ISSUED
        # Cause webhook to be emitted
        await ex_record.save(session, reason="Credential issued")
        # Exchange is completed, record can be cleaned up
        # But we'll leave it to the controller
        # await ex_record.delete_record(session)

    cred_response = {
        "credentials": [credential],
        "notification_id": ex_record.notification_id,
    }

    return web.json_response(cred_response)
