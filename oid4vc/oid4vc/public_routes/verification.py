"""OID4VP verification endpoints and helpers."""

import json
import logging
import time
import uuid
from secrets import token_urlsafe
from typing import Any, Dict

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    PresentationDefinition,
)
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import bytes_to_b64
from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
    match_info_schema,
)
from aries_askar import Key, KeyAlg
from base58 import b58decode
from marshmallow import fields

from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.jwk import DID_JWK
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
from .nonce import NONCE_BYTES

LOGGER = logging.getLogger(__name__)


class OID4VPRequestIDMatchSchema(OpenAPISchema):
    """Path parameters and validators for request taking request id."""

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "OID4VP Request identifier",
        },
    )


async def _retrieve_default_did(session: ProfileSession) -> DIDInfo | None:
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
