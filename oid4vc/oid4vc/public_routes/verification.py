"""OID4VP presentation verification endpoints."""

import json
import logging
import time
import uuid
from secrets import token_urlsafe
from typing import Any, Dict, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    PresentationDefinition,
)
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
    match_info_schema,
)
from marshmallow import fields

from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.jwt import jwt_sign
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.presentation_definition import OID4VPPresDef
from oid4vc.models.request import OID4VPRequest
from oid4vc.pex import (
    PexVerifyResult,
    PresentationExchangeEvaluator,
    PresentationSubmission,
)

from ..config import Config
from ..cred_processor import CredProcessors
from ..did_utils import retrieve_or_create_did_jwk
from .constants import NONCE_BYTES

LOGGER = logging.getLogger(__name__)


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


# ---------------------------------------------------------------------------
# X.509 identity – stores a certificate chain + signing key for x509_san_dns
# client_id_scheme in OID4VP request objects (JAR, RFC 9101).
# ---------------------------------------------------------------------------

X509_IDENTITY_RECORD_TYPE = "OID4VP.x509_identity"
X509_IDENTITY_RECORD_ID = "OID4VP.x509_identity"


async def _get_x509_identity(session: ProfileSession) -> Optional[Dict[str, Any]]:
    """Return stored X.509 identity dict, or None if not configured.

    The dict has the shape::

        {
            "cert_chain": ["<base64DER_leaf>", ...],  # leaf-first
            "verification_method": "did:jwk:...#0",
            "client_id": "acapy-verifier.example.com",
        }
    """
    storage = session.inject(BaseStorage)
    try:
        record = await storage.get_record(
            X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
        )
        return json.loads(record.value)
    except StorageNotFoundError:
        return None


@docs(tags=["oid4vp"], summary="Retrive OID4VP authorization request token")
@match_info_schema(OID4VPRequestIDMatchSchema())
async def get_request(request: web.Request):
    """Get an OID4VP Request token."""
    context: AdminRequestContext = request["context"]
    request_id = request.match_info["request_id"]
    pres_def = None
    dcql_query = None

    try:
        async with context.session() as session:
            record = await OID4VPRequest.retrieve_by_id(session, request_id)
            await record.delete_record(session)

            pres = await OID4VPPresentation.retrieve_by_request_id(
                session=session, request_id=request_id
            )

            if record.pres_def_id:
                pres_def = await OID4VPPresDef.retrieve_by_id(session, record.pres_def_id)
            elif record.dcql_query_id:
                dcql_query = await DCQLQuery.retrieve_by_id(session, record.dcql_query_id)
            jwk = await retrieve_or_create_did_jwk(session)
            x509_id = await _get_x509_identity(session)

            pres.state = OID4VPPresentation.REQUEST_RETRIEVED
            pres.nonce = token_urlsafe(NONCE_BYTES)
            # Use x509 client_id when configured (x509_san_dns scheme).
            # OID4VP Final (ID3+) encodes the scheme as a URI prefix in client_id:
            #   x509_san_dns:{dns_name}  (e.g. "x509_san_dns:acapy-tls-proxy.local")
            # This replaces the old separate client_id_scheme parameter.
            if x509_id:
                effective_client_id = f"x509_san_dns:{x509_id['client_id']}"
            else:
                effective_client_id = jwk.did
            pres.client_id = effective_client_id
            await pres.save(session=session, reason="Retrieved presentation request")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    now = int(time.time())
    config = Config.from_settings(context.settings)
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    # Use OID4VP_ENDPOINT when available (may differ from the OID4VCI endpoint;
    # e.g. behind a dedicated TLS-terminating proxy for conformance tests).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    payload = {
        "iss": effective_client_id,
        # NOTE: Do NOT include 'sub' equal to client_id in OID4VP JAR.
        # RFC 7519: sub identifies the principal that is the subject of the JWT,
        # but the JAR does not have a meaningful 'subject'.  Including sub=client_id
        # triggers a security warning (potential for use as client auth assertion).
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": str(uuid.uuid4()),
        # client_id: when using x509_san_dns the value is a DNS name that
        # matches the SAN of the leaf certificate.  For did:jwk the value is
        # the DID itself (scheme inferred from prefix, no explicit
        # client_id_scheme — see note below).
        # NOTE: Do NOT include "client_id_scheme" in OID4VP Final (ID3+): the
        # scheme is encoded as a URI prefix in client_id itself.
        # For x509_san_dns: client_id = "x509_san_dns:{dns_name}".
        # For did:jwk: client_id = the DID itself ("did:jwk:...").
        # The x5c cert chain in the JWT header establishes the x509 binding.
        # Do NOT add a separate client_id_scheme parameter — it causes failures.
        "client_id": effective_client_id,
        "response_uri": (
            f"{oid4vp_base}{subpath}/oid4vp/response/{pres.presentation_id}"
        ),
        "state": pres.presentation_id,
        "nonce": pres.nonce,
        "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA"],
        "response_types_supported": ["id_token", "vp_token"],
        "scopes_supported": ["openid", "vp_token"],
        "subject_types_supported": ["pairwise"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
        # OID4VP Final: vp_formats MUST be inside client_metadata when using
        # x509_san_dns (verifier has no metadata document URL).  Keep top-level
        # vp_formats as well for broad wallet compatibility.
        "client_metadata": {
            "vp_formats": record.vp_formats,
            "authorization_signed_response_alg": "ES256",
        },
        "vp_formats": record.vp_formats,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        # NOTE: Do NOT include "scope" here. The @openid4vc/openid4vp library
        # validates that EXACTLY ONE of {scope, presentation_definition,
        # presentation_definition_uri, dcql_query} is present. Including scope
        # alongside presentation_definition or dcql_query causes a validation error.
    }
    if pres_def is not None:
        payload["presentation_definition"] = pres_def.pres_def
    if dcql_query is not None:
        payload["dcql_query"] = dcql_query.record_value

    if x509_id:
        headers = {
            "x5c": x509_id["cert_chain"],
            "typ": "oauth-authz-req+jwt",
            "alg": "ES256",
        }
        signing_vm = x509_id["verification_method"]
    else:
        headers = {
            "kid": f"{jwk.did}#0",
            "typ": "oauth-authz-req+jwt",
        }
        signing_vm = f"{jwk.did}#0"

    token = await jwt_sign(
        profile=context.profile,
        payload=payload,
        headers=headers,
        verification_method=signing_vm,
    )

    LOGGER.debug("TOKEN: %s", token)

    return web.Response(text=token)


class OID4VPPresentationIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    presentation_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Presentation identifier",
        },
    )


class PostOID4VPResponseSchema(OpenAPISchema):
    """Schema for ..."""

    presentation_submission = fields.Str(required=False, metadata={"description": ""})

    vp_token = fields.Str(
        required=True,
        metadata={
            "description": "",
        },
    )

    state = fields.Str(
        required=False, metadata={"description": "State describing the presentation"}
    )


async def verify_dcql_presentation(
    profile,
    vp_token: Dict[str, Any],
    dcql_query_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s", vp_token)

    async with profile.session() as session:
        dcql_query = await DCQLQuery.retrieve_by_id(
            session,
            dcql_query_id,
        )

    evaluator = DCQLQueryEvaluator.compile(dcql_query)
    result = await evaluator.verify(profile, vp_token, presentation)
    return result


async def verify_pres_def_presentation(
    profile,
    submission: PresentationSubmission,
    vp_token: str,
    pres_def_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s %s", submission, vp_token)

    processors = profile.inject(CredProcessors)
    if not submission.descriptor_maps:
        raise web.HTTPBadRequest(reason="Descriptor map of submission must not be empty")

    # TODO: Support longer descriptor map arrays
    if len(submission.descriptor_maps) != 1:
        raise web.HTTPBadRequest(
            reason="Descriptor map of length greater than 1 is not supported at this time"
        )

    verifier = processors.pres_verifier_for_format(submission.descriptor_maps[0].fmt)
    LOGGER.debug("VERIFIER: %s", verifier)

    vp_result = await verifier.verify_presentation(
        profile=profile,
        presentation=vp_token,
        presentation_record=presentation,
    )

    if not vp_result.verified:
        error_msg = (
            vp_result.payload.get("error", "Presentation verification failed")
            if isinstance(vp_result.payload, dict)
            else "Presentation verification failed"
        )
        if isinstance(error_msg, list):
            error_msg = "; ".join(str(e) for e in error_msg)
        return PexVerifyResult(details=str(error_msg))

    async with profile.session() as session:
        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
            session,
            pres_def_id,
        )

        pres_def = PresentationDefinition.deserialize(pres_def_entry.pres_def)

    evaluator = PresentationExchangeEvaluator.compile(pres_def)

    # For mso_mdoc presentations, vp_result.payload is an already-decoded claims
    # dict.  The presentation_submission from wallets (e.g. waltid) typically
    # references $.documents[N] which is a path into the raw DeviceResponse CBOR,
    # not the decoded dict.  Wrap the decoded payload so that $.documents[0]
    # correctly resolves to the pre-verified claims.
    item = submission.descriptor_maps[0]
    if (
        item.path_nested
        and item.path_nested.path
        and ".documents[" in item.path_nested.path
    ):
        eval_presentation: dict = {"documents": [vp_result.payload]}
    else:
        eval_presentation = vp_result.payload

    result = await evaluator.verify(profile, submission, eval_presentation)
    return result


@docs(tags=["oid4vp"], summary="Provide OID4VP presentation")
@match_info_schema(OID4VPPresentationIDMatchSchema())
@form_schema(PostOID4VPResponseSchema())
async def post_response(request: web.Request):
    """Post an OID4VP Response."""
    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    form = await request.post()

    # DEBUG: log raw POST form body
    LOGGER.debug("OID4VP POST form keys: %s", list(form.keys()))
    raw_vp_token = form.get("vp_token")
    LOGGER.debug(
        "OID4VP POST vp_token (first 200 chars): %r",
        raw_vp_token[:200] if isinstance(raw_vp_token, str) else raw_vp_token,
    )
    LOGGER.debug(
        "OID4VP POST presentation_submission (first 500 chars): %r",
        form.get("presentation_submission", "<MISSING>")[:500]
        if isinstance(form.get("presentation_submission"), str)
        else form.get("presentation_submission", "<MISSING>"),
    )
    LOGGER.debug("OID4VP POST state: %r", form.get("state"))

    # presentation_submission is only present for PEX (pres_def) presentations;
    # DCQL presentations omit it and send vp_token as a JSON object instead.
    raw_submission = form.get("presentation_submission")
    presentation_submission = (
        PresentationSubmission.from_json(raw_submission)
        if isinstance(raw_submission, str)
        else None
    )

    vp_token = form.get("vp_token")
    state = form.get("state")

    if state and state != presentation_id:
        raise web.HTTPBadRequest(reason="`state` must match the presentation id")

    async with context.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    try:
        if not isinstance(vp_token, str):
            raise web.HTTPBadRequest(reason="vp_token must be a string")

        if record.pres_def_id:
            if presentation_submission is None:
                raise web.HTTPBadRequest(
                    reason="presentation_submission is required for PEX presentations"
                )
            verify_result = await verify_pres_def_presentation(
                profile=context.profile,
                submission=presentation_submission,
                vp_token=vp_token,
                pres_def_id=record.pres_def_id,
                presentation=record,
            )
        elif record.dcql_query_id:
            verify_result = await verify_dcql_presentation(
                profile=context.profile,
                vp_token=json.loads(vp_token),
                dcql_query_id=record.dcql_query_id,
                presentation=record,
            )
        else:
            LOGGER.error("Record %s has neither pres_def_id or dcql_query_id", record)
            raise web.HTTPInternalServerError(reason="Something went wrong")

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        # Catch all other exceptions (e.g. CredProcessorError, unsupported format),
        # save the record as invalid so the holder gets a response and callers can
        # observe the failure rather than timing out on request-retrieved.
        error_msg = str(err)
        LOGGER.exception(
            "Unexpected error processing presentation %s: %s",
            presentation_id,
            error_msg,
        )
        record.state = OID4VPPresentation.PRESENTATION_INVALID
        record.errors = [f"Processing error: {error_msg}"]
        record.verified = False
        record.matched_credentials = {}
        async with context.session() as session:
            await record.save(session, reason="Presentation processing failed")
        return web.json_response({})

    if verify_result.verified:
        record.state = OID4VPPresentation.PRESENTATION_VALID
    else:
        record.state = OID4VPPresentation.PRESENTATION_INVALID
        assert verify_result.details
        record.errors = [verify_result.details]

    record.verified = verify_result.verified
    record.matched_credentials = (
        verify_result.descriptor_id_to_claims
        if isinstance(verify_result, PexVerifyResult)
        else verify_result.cred_query_id_to_claims
    )

    async with context.session() as session:
        await record.save(
            session,
            reason=f"Presentation verified: {verify_result.verified}",
        )

    LOGGER.debug("Presentation result: %s", record.verified)
    # OID4VP Final §6.2: verifier MUST return a JSON response body.
    # If no redirect_uri is required, return an empty JSON object.
    return web.json_response({})
