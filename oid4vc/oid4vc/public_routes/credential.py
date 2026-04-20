"""Credential issuance endpoints for OID4VCI."""

import logging
from typing import List, Optional
from urllib.parse import quote
import json

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..cred_processor import CredProcessorError, CredProcessors
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential
from ..routes import CredOfferQuerySchema, CredOfferResponseSchemaVal
from ..routes.helpers import _parse_cred_offer
from .token import check_token, handle_proof_of_posession

LOGGER = logging.getLogger(__name__)


def _vc_error(
    status: int, error: str, description: str | None = None
) -> web.HTTPException:
    """Build a JSON-formatted OID4VCI error response per spec §7.3.2."""
    body: dict = {"error": error}
    if description:
        body["error_description"] = description
    kwargs = {"text": json.dumps(body), "content_type": "application/json"}
    mapping = {400: web.HTTPBadRequest, 401: web.HTTPUnauthorized, 404: web.HTTPNotFound}
    cls = mapping.get(status, web.HTTPInternalServerError)
    return cls(**kwargs)


@docs(tags=["oid4vci"], summary="Dereference a credential offer.")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
async def dereference_cred_offer(request: web.BaseRequest):
    """Dereference a credential offer.

    Reference URI is acquired from the /oid4vci/credential-offer-by-ref endpoint
    (see routes.get_cred_offer_by_ref()).
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    return web.json_response(
        {
            "offer": offer,
            "credential_offer": f"openid-credential-offer://?credential_offer={quote(json.dumps(offer))}",
        }
    )


def types_are_subset(request: Optional[List[str]], supported: Optional[List[str]]):
    """Compare types."""
    if request is None:
        return False
    if supported is None:
        return False
    return set(request).issubset(set(supported))


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema for the /credential endpoint (OID4VCI 1.0).

    Per OID4VCI 1.0 § 7.2: credential_identifier and format are mutually exclusive.
    Either credential_identifier (1.0) OR format (draft) must be provided.
    """

    credential_identifier = fields.Str(
        required=False,
        metadata={
            "description": "OID4VCI 1.0: Identifier of the credential configuration.",
            "example": "UniversityDegreeCredential",
        },
    )
    format = fields.Str(
        required=False,
        metadata={
            "description": "Draft spec: Credential format.",
            "example": "jwt_vc_json",
        },
    )
    type = fields.List(
        fields.Str(),
        metadata={"description": "Credential types (optional)."},
    )
    proof = fields.Dict(
        required=False, metadata={"description": "Proof of possession (key binding)."}
    )


@docs(tags=["oid4vc"], summary="Issue a credential")
@request_schema(IssueCredentialRequestSchema())
async def issue_cred(request: web.Request):
    """The Credential Endpoint issues a Credential (OID4VCI 1.0).

    As validated upon presentation of a valid Access Token.
    Supports both credential_identifier (OID4VCI 1.0) and format (draft spec).
    """
    context: AdminRequestContext = request["context"]
    # check_token raises HTTPUnauthorized on auth failures — propagate as-is.
    token_result = await check_token(context, request.headers.get("Authorization"))
    refresh_id = token_result.payload["sub"]
    req_body = await request.json()
    LOGGER.info("request: %s", req_body)

    try:
        return await _issue_cred_inner(context, token_result, refresh_id, req_body)
    except web.HTTPException as exc:
        if exc.status in (401, 403):
            raise  # propagate auth errors unchanged
        # ACA-Py's ready_middleware intercepts web.HTTPBadRequest and re-raises
        # it as HTTPBadRequest(reason=str(e)), stripping our JSON body and
        # setting wrong Content-Type.  By catching here and returning a Response
        # directly we bypass the middleware.
        err_body: dict = {}
        if exc.text:
            try:
                err_body = json.loads(exc.text)
            except (json.JSONDecodeError, ValueError):
                err_body = {
                    "error": "invalid_credential_request",
                    "error_description": exc.reason,
                }
        else:
            err_body = {
                "error": "invalid_credential_request",
                "error_description": exc.reason or "Bad Request",
            }
        return web.json_response(err_body, status=exc.status)


async def _issue_cred_inner(context, token_result, refresh_id, req_body):
    """Inner implementation of issue_cred; all errors raised as HTTPException."""
    # OID4VCI 1.0 § 7.2: credential_identifier and format are mutually exclusive.
    # Also accept credential_configuration_id (OID4VCI 1.0 final spec field name).
    # Track which field was used in the request to return the correct error code.
    raw_credential_identifier = req_body.get("credential_identifier")
    raw_credential_config_id = req_body.get("credential_configuration_id")
    credential_identifier = raw_credential_identifier or raw_credential_config_id
    format_field = req_body.get("format")

    if credential_identifier and format_field:
        raise _vc_error(
            400,
            "invalid_credential_request",
            "credential_identifier and format are mutually exclusive",
        )

    if not credential_identifier and not format_field:
        raise _vc_error(
            400,
            "invalid_credential_request",
            "credential_identifier or format is required",
        )

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
        # OID4VCI 1.0 §7.5: if the exchange is in STATE_ISSUED (already issued),
        # a second attempt with the same nonce is a nonce replay → invalid_nonce.
        try:
            async with context.profile.session() as session:
                issued = await OID4VCIExchangeRecord.retrieve_by_tag_filter(
                    session,
                    {
                        "refresh_id": refresh_id,
                        "state": OID4VCIExchangeRecord.STATE_ISSUED,
                    },
                )
        except Exception:
            issued = None
        if issued:
            raise _vc_error(
                400, "invalid_nonce", "Nonce already used; credential was already issued."
            )
        raise _vc_error(
            400, "invalid_credential_request", "No credential offer available."
        ) from err
    except (StorageError, BaseModelError) as err:
        raise _vc_error(400, "invalid_credential_request", err.roll_up) from err

    if not supported.format:
        raise _vc_error(
            400, "invalid_credential_request", "SupportedCredential missing format."
        )

    # Handle both OID4VCI 1.0 (credential_identifier/credential_configuration_id)
    # and draft spec (format). Return spec-correct error codes per OID4VCI 1.0 §7.3.1.
    if credential_identifier:
        # OID4VCI 1.0: Match by credential_identifier or credential_configuration_id.
        if supported.identifier != credential_identifier:
            # Distinguish request type for correct error code.
            if raw_credential_identifier:
                raise _vc_error(
                    400,
                    "invalid_credential_identifier",
                    "credential_identifier does not match offer",
                )
            else:
                raise _vc_error(
                    400,
                    "invalid_credential_configuration",
                    "credential_configuration_id is not supported",
                )
    else:
        # Draft spec: Match by format
        if supported.format != format_field:
            raise _vc_error(
                400,
                "invalid_credential_request",
                "Requested format does not match offer.",
            )

    authorization_details = token_result.payload.get("authorization_details", None)
    if authorization_details:
        found = any(
            isinstance(ad, dict)
            and ad.get("credential_configuration_id") == supported.identifier
            for ad in authorization_details
        )
        if not found:
            raise _vc_error(
                400,
                "invalid_credential_request",
                f"{supported.identifier} is not authorized by the token.",
            )

    # c_nonce may be None when the OID4VCI 1.0 /nonce endpoint is used.
    # handle_proof_of_posession handles c_nonce=None by calling Nonce.redeem_by_value,
    # which validates nonces issued by the /nonce endpoint with replay protection.
    c_nonce = token_result.payload.get("c_nonce") or ex_record.nonce

    # Normalize proof: accept both 'proof' (singular, draft spec) and
    # 'proofs.jwt' (plural array, OID4VCI 1.0 final spec)
    if "proof" in req_body:
        proof_value = req_body["proof"]
    elif "proofs" in req_body and isinstance(req_body["proofs"], dict):
        jwt_proofs = req_body["proofs"].get("jwt", [])
        if not jwt_proofs:
            raise _vc_error(
                400, "invalid_proof", f"proofs.jwt is empty for {supported.format}"
            )
        if len(jwt_proofs) > 1:
            raise _vc_error(
                400,
                "invalid_proof",
                f"proofs.jwt contains {len(jwt_proofs)} entries but batch "
                "issuance is not supported; send exactly one proof.",
            )
        # Normalize to the expected structure
        proof_value = {"proof_type": "jwt", "jwt": jwt_proofs[0]}
    else:
        raise _vc_error(400, "invalid_proof", f"proof is required for {supported.format}")

    pop = await handle_proof_of_posession(context.profile, proof_value, c_nonce)

    if not pop.verified:
        raise _vc_error(400, "invalid_proof", "Proof signature verification failed.")

    try:
        processors = context.inject(CredProcessors)
        processor = processors.issuer_for_format(supported.format)

        credential = await processor.issue(req_body, supported, ex_record, pop, context)
    except CredProcessorError as e:
        raise _vc_error(400, "invalid_credential_request", e.message)

    async with context.session() as session:
        ex_record.state = OID4VCIExchangeRecord.STATE_ISSUED
        # Cause webhook to be emitted
        await ex_record.save(session, reason="Credential issued")

    # OID4VCI 1.0 §7.3.1: response MUST contain `credentials` (array) or `transaction_id`.
    # Only return the 'credentials' array (OID4VCI 1.0), not the legacy 'credential' key.
    cred_response = {
        "credentials": [{"format": supported.format, "credential": credential}]
    }
    if ex_record.notification_id:
        cred_response["notification_id"] = ex_record.notification_id

    return web.json_response(cred_response)
