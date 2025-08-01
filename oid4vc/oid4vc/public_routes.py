"""Public routes for OID4VC."""

import datetime
import json
import logging
import time
import uuid
from secrets import token_urlsafe
from urllib.parse import quote
from typing import Any, Dict, List, Optional

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    PresentationDefinition,
)
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet, WalletError
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import JWTVerifyResult, b64_to_dict
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_askar import Key, KeyAlg
from base58 import b58decode
from marshmallow import fields

from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.jwk import DID_JWK
from oid4vc.jwt import jwt_sign, jwt_verify, key_material_for_kid
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.presentation_definition import OID4VPPresDef
from oid4vc.models.request import OID4VPRequest
from oid4vc.pex import (
    PexVerifyResult,
    PresentationExchangeEvaluator,
    PresentationSubmission,
)

from .config import Config
from .cred_processor import CredProcessorError, CredProcessors
from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult
from .routes import _parse_cred_offer, CredOfferQuerySchema, CredOfferResponseSchemaVal
from .status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
NONCE_BYTES = 16
EXPIRES_IN = 86400


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


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={"description": "The credential issuer endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={"description": "The credential endpoint."},
    )
    credentials_supported = fields.List(
        fields.Dict(),
        metadata={"description": "The supported credentials."},
    )
    authorization_server = fields.Str(
        required=False,
        metadata={"description": "The authorization server endpoint. Currently ignored."},
    )
    batch_credential_endpoint = fields.Str(
        required=False,
        metadata={"description": "The batch credential endpoint. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint."""
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        metadata = {
            "credential_issuer": f"{public_url}{subpath}",
            "credential_endpoint": f"{public_url}{subpath}/credential",
            "credentials_supported": [
                supported.to_issuer_metadata() for supported in credentials_supported
            ],
        }

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)


class GetTokenSchema(OpenAPISchema):
    """Schema for ..."""

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)


@docs(tags=["oid4vc"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""
    context: AdminRequestContext = request["context"]
    form = await request.post()
    LOGGER.debug(f"Token request: {form}")
    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        raise web.HTTPBadRequest(reason="grant_type not supported")

    pre_authorized_code = form.get("pre-authorized_code")
    if not pre_authorized_code or not isinstance(pre_authorized_code, str):
        raise web.HTTPBadRequest(reason="pre-authorized_code is missing or invalid")

    user_pin = request.query.get("user_pin")
    try:
        async with context.profile.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                session, pre_authorized_code
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if record.pin is not None:
        if user_pin is None:
            raise web.HTTPBadRequest(reason="user_pin is required")
        if user_pin != record.pin:
            raise web.HTTPBadRequest(reason="pin is invalid")

    payload = {
        "id": record.exchange_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }
    async with context.profile.session() as session:
        try:
            token = await jwt_sign(
                context.profile,
                headers={},
                payload=payload,
                verification_method=record.verification_method,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            raise web.HTTPBadRequest(reason="Bad did or verification method") from err

        record.token = token
        record.nonce = token_urlsafe(NONCE_BYTES)
        await record.save(
            session,
            reason="Created new token",
        )

    return web.json_response(
        {
            "access_token": record.token,
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
            "c_nonce": record.nonce,
            # I don't think it makes sense for the two expirations to be
            # different; coordinating a new c_nonce separate from a token
            # refresh seems like a pain.
            "c_nonce_expires_in": EXPIRES_IN,
        }
    )


async def check_token(
    profile: Profile, auth_header: Optional[str] = None
) -> JWTVerifyResult:
    """Validate the OID4VCI token."""
    if not auth_header:
        raise web.HTTPUnauthorized()  # no authentication

    scheme, cred = auth_header.split(" ")
    if scheme.lower() != "bearer":
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    result = await jwt_verify(profile, cred)
    if not result.verified:
        raise web.HTTPUnauthorized()  # Invalid credentials

    if result.payload["exp"] < datetime.datetime.utcnow().timestamp():
        raise web.HTTPUnauthorized()  # Token expired

    return result


async def handle_proof_of_posession(profile: Profile, proof: Dict[str, Any], nonce: str):
    """Handle proof of posession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    if headers.get("typ") != "openid4vci-proof+jwt":
        raise web.HTTPBadRequest(reason="Invalid proof: wrong typ.")

    if "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(reason="Invalid kid") from exc
    elif "jwk" in headers:
        key = Key.from_jwk(headers["jwk"])
    elif "x5c" in headers:
        raise web.HTTPBadRequest(reason="x5c not supported")
    else:
        raise web.HTTPBadRequest(reason="No key material in proof")

    payload = b64_to_dict(encoded_payload)

    if nonce != payload.get("nonce"):
        raise web.HTTPBadRequest(
            reason="Invalid proof: wrong nonce.",
        )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg"),
    )
    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=headers.get("jwk"),
    )


def types_are_subset(request: Optional[List[str]], supported: Optional[List[str]]):
    """Compare types."""
    if request is None:
        return False
    if supported is None:
        return False
    return set(request).issubset(set(supported))


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema for the /credential endpoint."""

    format = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )
    types = fields.List(
        fields.Str(),
        metadata={"description": ""},
    )
    proof = fields.Dict(metadata={"description": ""})


@docs(tags=["oid4vc"], summary="Issue a credential")
@request_schema(IssueCredentialRequestSchema())
async def issue_cred(request: web.Request):
    """The Credential Endpoint issues a Credential.

    As validated upon presentation of a valid Access Token.
    """
    context: AdminRequestContext = request["context"]
    token_result = await check_token(
        context.profile, request.headers.get("Authorization")
    )
    exchange_id = token_result.payload["id"]
    body = await request.json()
    LOGGER.info(f"request: {body}")
    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if supported.format != body.get("format"):
        raise web.HTTPBadRequest(reason="Requested format does not match offer.")

    if not supported.format:
        raise web.HTTPBadRequest(reason="SupportedCredential missing format identifier")

    if ex_record.nonce is None:
        raise web.HTTPBadRequest(
            reason="Invalid exchange; no offer created for this request"
        )

    if supported.format_data is None:
        LOGGER.error(f"No format_data for supported credential {supported.format}.")
        raise web.HTTPInternalServerError()

    if "proof" not in body:
        raise web.HTTPBadRequest(reason=f"proof is required for {supported.format}")

    pop = await handle_proof_of_posession(context.profile, body["proof"], ex_record.nonce)
    if not pop.verified:
        raise web.HTTPBadRequest(reason="Invalid proof")

    try:
        processors = context.inject(CredProcessors)
        processor = processors.issuer_for_format(supported.format)

        credential = await processor.issue(body, supported, ex_record, pop, context)
    except CredProcessorError as e:
        raise web.HTTPBadRequest(reason=e.message)

    async with context.session() as session:
        ex_record.state = OID4VCIExchangeRecord.STATE_ISSUED
        # Cause webhook to be emitted
        await ex_record.save(session, reason="Credential issued")
        # Exchange is completed, record can be cleaned up
        # But we'll leave it to the controller
        # await ex_record.delete_record(session)

    return web.json_response(
        {
            "format": supported.format,
            "credential": credential,
        }
    )


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


async def _retrieve_default_did(session: ProfileSession) -> Optional[DIDInfo]:
    """Retrieve default DID from the store.

    Args:
        session: An active profile session

    Returns:
        Optional[DIDInfo]: retrieved DID info or None if not found

    """
    storage = session.inject(BaseStorage)
    wallet = session.inject(BaseWallet)
    try:
        record = await storage.get_record(
            record_type="OID4VP.default",
            record_id="OID4VP.default",
        )
        info = json.loads(record.value)
        info.update(record.tags)
        did_info = await wallet.get_local_did(record.tags["did"])

        return did_info
    except StorageNotFoundError:
        return None


async def _create_default_did(session: ProfileSession) -> DIDInfo:
    """Create default DID.

    Args:
        session: An active profile session

    Returns:
        DIDInfo: created default DID info

    """
    wallet = session.inject(BaseWallet)
    storage = session.inject(BaseStorage)
    key = await wallet.create_key(ED25519)
    jwk = json.loads(
        Key.from_public_bytes(KeyAlg.ED25519, b58decode(key.verkey)).get_jwk_public()
    )
    jwk["use"] = "sig"
    jwk = json.dumps(jwk)

    did_jwk = f"did:jwk:{bytes_to_b64(jwk.encode(), urlsafe=True, pad=False)}"

    did_info = DIDInfo(did_jwk, key.verkey, {}, DID_JWK, ED25519)
    info = await wallet.store_did(did_info)

    record = StorageRecord(
        type="OID4VP.default",
        value=json.dumps({"verkey": info.verkey, "metadata": info.metadata}),
        tags={"did": info.did},
        id="OID4VP.default",
    )
    await storage.add_record(record)
    return info


async def retrieve_or_create_did_jwk(session: ProfileSession):
    """Retrieve default did:jwk info, or create it."""

    key = await _retrieve_default_did(session)
    if key:
        return key

    return await _create_default_did(session)


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
            pres.state = OID4VPPresentation.REQUEST_RETRIEVED
            pres.nonce = token_urlsafe(NONCE_BYTES)
            await pres.save(session=session, reason="Retrieved presentation request")

            if record.pres_def_id:
                pres_def = await OID4VPPresDef.retrieve_by_id(session, record.pres_def_id)
            elif record.dcql_query_id:
                dcql_query = await DCQLQuery.retrieve_by_id(session, record.dcql_query_id)
            jwk = await retrieve_or_create_did_jwk(session)

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
    payload = {
        "iss": jwk.did,
        "sub": jwk.did,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": str(uuid.uuid4()),
        "client_id": config.endpoint,
        "response_uri": (
            f"{config.endpoint}{subpath}/oid4vp/response/{pres.presentation_id}"
        ),
        "state": pres.presentation_id,
        "nonce": pres.nonce,
        "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA"],
        "response_types_supported": ["id_token", "vp_token"],
        "scopes_supported": ["openid", "vp_token"],
        "subject_types_supported": ["pairwise"],
        "subject_syntax_types_supported": ["urn:ietf:params:oauth:jwk-thumbprint"],
        "vp_formats": record.vp_formats,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "scope": "vp_token",
    }
    if pres_def is not None:
        payload["presentation_definition"] = pres_def.pres_def
    if dcql_query is not None:
        payload["dcql_query"] = dcql_query.record_value

    headers = {
        "kid": f"{jwk.did}#0",
        "typ": "oauth-authz-req+jwt",
    }

    token = await jwt_sign(
        profile=context.profile,
        payload=payload,
        headers=headers,
        verification_method=f"{jwk.did}#0",
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
    profile: Profile,
    vp_token: Dict[str, Any],
    dcql_query_id: str,
    presentation: OID4VPPresentation,
):
    """Verify a received presentation."""

    LOGGER.debug("Got: %s", vp_token)

    async with profile.session() as session:
        pres_def_entry = await DCQLQuery.retrieve_by_id(
            session,
            dcql_query_id,
        )

        dcql_query = DCQLQuery.deserialize(pres_def_entry)

    evaluator = DCQLQueryEvaluator.compile(dcql_query)
    result = await evaluator.verify(profile, vp_token, presentation)
    return result


async def verify_pres_def_presentation(
    profile: Profile,
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

    async with profile.session() as session:
        pres_def_entry = await OID4VPPresDef.retrieve_by_id(
            session,
            pres_def_id,
        )

        pres_def = PresentationDefinition.deserialize(pres_def_entry.pres_def)

    evaluator = PresentationExchangeEvaluator.compile(pres_def)
    result = await evaluator.verify(profile, submission, vp_result.payload)
    return result


@docs(tags=["oid4vp"], summary="Provide OID4VP presentation")
@match_info_schema(OID4VPPresentationIDMatchSchema())
@form_schema(PostOID4VPResponseSchema())
async def post_response(request: web.Request):
    """Post an OID4VP Response."""
    context: AdminRequestContext = request["context"]
    presentation_id = request.match_info["presentation_id"]

    form = await request.post()

    raw_submission = form.get("presentation_submission")
    assert isinstance(raw_submission, str)
    presentation_submission = PresentationSubmission.from_json(raw_submission)

    vp_token = form.get("vp_token")
    state = form.get("state")

    if state and state != presentation_id:
        raise web.HTTPBadRequest(reason="`state` must match the presentation id")

    async with context.session() as session:
        record = await OID4VPPresentation.retrieve_by_id(session, presentation_id)

    try:
        assert isinstance(vp_token, str)

        if record.pres_def_id:
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
    return web.Response(status=200)


class StatusListMatchSchema(OpenAPISchema):
    """Path parameters and validators for status list request."""

    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
        },
    )


@docs(tags=["status-list"], summary="Get status list by list number")
@match_info_schema(StatusListMatchSchema())
async def get_status_list(request: web.Request):
    """Get status list."""

    context: AdminRequestContext = request["context"]
    list_number = request.match_info["list_number"]

    status_handler = context.inject_or(StatusHandler)
    if status_handler:
        status_list = await status_handler.get_status_list(context, list_number)
        return web.Response(text=status_list)


async def register(app: web.Application, multitenant: bool, context: InjectionContext):
    """Register routes with support for multitenant mode.

    Adds the subpath with Wallet ID as a path parameter if multitenant is True.
    """
    subpath = "/tenant/{wallet_id}" if multitenant else ""
    routes = [
        web.get(
            f"{subpath}/oid4vci/dereference-credential-offer",
            dereference_cred_offer,
            allow_head=False,
        ),
        web.get(
            f"{subpath}/.well-known/openid-credential-issuer",
            credential_issuer_metadata,
            allow_head=False,
        ),
        # TODO Add .well-known/did-configuration.json
        # Spec: https://identity.foundation/.well-known/resources/did-configuration/
        web.post(f"{subpath}/token", token),
        web.post(f"{subpath}/credential", issue_cred),
        web.get(f"{subpath}/oid4vp/request/{{request_id}}", get_request),
        web.post(f"{subpath}/oid4vp/response/{{presentation_id}}", post_response),
    ]
    # Conditionally add status route
    if context.inject_or(StatusHandler):
        routes.append(
            web.get(
                f"{subpath}/status/{{list_number}}", get_status_list, allow_head=False
            )
        )
    # Add the routes to the application
    app.add_routes(routes)
