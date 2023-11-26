"""Public routes for OID4VCI."""

import datetime
import logging
from typing import Optional
import uuid
from aries_cloudagent.core.profile import Profile, ProfileSession
from aries_cloudagent.wallet.error import WalletNotFoundError
import jwt as JWT
from secrets import token_urlsafe

from aiohttp import web
from aiohttp_apispec import (
    docs,
    form_schema,
    request_schema,
)
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.wallet.jwt import JWTVerifyResult, jwt_sign, jwt_verify
from aries_cloudagent.wallet.base import BaseWallet, WalletError
from aries_cloudagent.wallet.did_method import KEY
from aries_cloudagent.wallet.key_type import ED25519
from marshmallow import fields

from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .config import Config

LOGGER = logging.getLogger(__name__)


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


class TokenRequestSchema(OpenAPISchema):
    """Request schema for the /token endpoint."""

    client_id = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )


class GetTokenSchema(OpenAPISchema):
    """Schema for ..."""

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)


@docs(tags=["oid4vci"], summary="Get credential issuer metadata")
# @querystring_schema(TokenRequestSchema())
async def oid_cred_issuer(request: web.Request):
    """Credential issuer metadata endpoint."""
    profile = request["context"].profile
    config = Config.from_context(profile.context)
    public_url = config.endpoint

    # Wallet query to retrieve credential definitions
    tag_filter = {}  # {"type": {"$in": ["sd_jwt", "jwt_vc_json"]}}
    async with profile.session() as session:
        credentials_supported = await SupportedCredential.query(session, tag_filter)

    metadata = {
        "credential_issuer": f"{public_url}/",  # TODO: update path with wallet id
        "credential_endpoint": f"{public_url}/credential",
        "credentials_supported": [
            supported.to_issuer_metadata() for supported in credentials_supported
        ],
        # "authorization_server": f"{public_url}/auth-server",
        # "batch_credential_endpoint": f"{public_url}/batch_credential",
    }

    return web.json_response(metadata)


async def check_token(
    profile: Profile, auth_header: Optional[str] = None
) -> JWTVerifyResult:
    """Validate the OID4VCI token."""
    if not auth_header:
        raise web.HTTPUnauthorized()  # no authentication

    scheme, cred = auth_header.split(" ")
    if scheme.lower() != "bearer":
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    jwt_header = JWT.get_unverified_header(cred)
    if "did:key:" not in jwt_header["kid"]:
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    result = await jwt_verify(profile, cred)
    if not result.valid:
        raise web.HTTPUnauthorized()  # Invalid credentials

    return result


def filter_subjects(types, subjects, claims):  # -> dict[Any, Any]:
    """Filters subjects only to supported ones."""
    attributes = set()
    for _type in types:
        attributes.update(claims[_type])
    return {key: value for (key, value) in subjects.items() if key in attributes}


@docs(tags=["oid4vci"], summary="Issue a credential")
@request_schema(IssueCredentialRequestSchema())
async def issue_cred(request: web.Request):
    """The Credential Endpoint issues a Credential.

    As validated upon presentation of a valid Access Token .
    """
    context: AdminRequestContext = request["context"]
    token_result = await check_token(
        context.profile, request.headers.get("Authorization")
    )
    exchange_id = token_result.payload["id"]

    # TODO: check scope???
    context = request["context"]
    body = await request.json()
    LOGGER.info(f"request: {body}")
    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            assert ex_record.supported_cred_id
            LOGGER.info(f"ex record: {ex_record}")
            LOGGER.info(f"supported_cred_id: {ex_record.supported_cred_id}")
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
            LOGGER.info(f"sup record: {supported}")
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    # TODO: improve types checking
    # if supported.format_data and body.get("types")[0] in supported.format_data.get(
    #     "types"
    # ):
    #     raise web.HTTPBadRequest(reason="Requested types does not match offer.")
    if supported.format != body.get("format"):
        raise web.HTTPBadRequest(reason="Requested format does not match offer.")
    if supported.format != "jwt_vc_json":
        raise web.HTTPUnprocessableEntity(reason="Only jwt_vc_json is supported.")

    current_time = datetime.datetime.now(datetime.timezone.utc)
    current_time_unix_timestamp = int(current_time.timestamp())
    formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    cred_id = str(uuid.uuid4())
    kid = None
    if proof := body.get("proof"):
        LOGGER.info(f"proof: {proof}")
        try:
            header = JWT.get_unverified_header(proof["jwt"])
            kid = header.get("kid")
            decoded_payload = JWT.decode(
                proof["jwt"], options={"verify_signature": False}
            )  # TODO: verify proof
            nonce = decoded_payload.get("nonce")  # TODO: why is this not c_nonce?
            if ex_record.nonce != nonce:
                raise web.HTTPBadRequest(
                    reason="Invalid proof: wrong nonce.",
                )
            # cleanup
            # TODO: cleanup exchange record, possible replay attack
        except JWT.DecodeError:
            print("Error decoding JWT. Invalid token or format.")

    payload = {
        # "format": "jwt_vc_json",
        # "types": cred_req.types,
        "vc": {
            **(supported.vc_additional_data or {}),
            "id": cred_id,
            "issuer": ex_record.verification_method,
            "issuanceDate": formatted_time,
            "credentialSubject": {
                **(ex_record.credential_subject or {}),
                "id": kid,  # TODO This might be None!
            },
        },
        "iss": ex_record.verification_method,
        "nbf": current_time_unix_timestamp,
        "jti": cred_id,
        "sub": kid,  # TODO This might be None!
    }

    jws = await jwt_sign(
        context.profile, {}, payload, verification_method=ex_record.verification_method
    )
    return web.json_response(
        {
            "format": "jwt_vc_json",
            "credential": jws,
        }
    )


async def create_did(session: ProfileSession):
    """Create a new DID."""
    key_type = ED25519
    wallet = session.inject(BaseWallet)
    try:
        return await wallet.create_local_did(method=KEY, key_type=key_type)
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def get_token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""
    LOGGER.info(f"request: {request.get('form')}")
    request["form"].get("grant_type", "")
    pre_authorized_code = request["form"].get("pre_authorized_code")
    if not pre_authorized_code:
        raise web.HTTPBadRequest()
    # user_pin = request.query.get("user_pin")
    context = request["context"]
    ex_record = None
    try:
        async with context.profile.session() as session:
            _filter = {
                "code": pre_authorized_code,
                # "user_pin": user_pin
            }
            records = await OID4VCIExchangeRecord.query(session, _filter)
            ex_record: OID4VCIExchangeRecord = records[0]
            if not ex_record or not ex_record.code:  # TODO: check pin
                return web.json_response({})  # TODO: report failure?

            # if ex_record.supported_cred_id:
            #    sup_cred_record: SupportedCredential = (
            #        await SupportedCredential.query(
            #            session, {"identifier": ex_record.supported_cred_id}
            #        )
            #    )[0]
            signing_did = await create_did(session)
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    # LOGGER.info(f"supported credential report: {sup_cred_record}")
    # scopes = sup_cred_record.scope
    payload = {
        "scope": ex_record.supported_cred_id,
        "id": ex_record.exchange_id,
    }
    async with context.profile.session() as session:
        signing_did = await create_did(session)

        try:
            _jwt = await jwt_sign(
                context.profile,
                headers={},
                payload=payload,
                did=signing_did.did,
            )
        except ValueError as err:
            raise web.HTTPBadRequest(reason="Bad did or verification method") from err
        except WalletNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err
        except WalletError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
        # update record with nonce and jwt
        ex_record.token = _jwt
        ex_record.nonce = token_urlsafe(16)
        await ex_record.save(
            session,
            reason="Created new token",
        )

    return web.json_response(
        {
            "access_token": ex_record.token,
            "token_type": "Bearer",
            "expires_in": "300",
            "c_nonce": ex_record.nonce,
            "c_nonce_expires_in": "86400",  # TODO: enforce this
        }
    )


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/.well-known/openid-credential-issuer",
                oid_cred_issuer,
                allow_head=False,
            ),
            web.post("/credential", issue_cred),
            web.post("/token", get_token),
        ]
    )
