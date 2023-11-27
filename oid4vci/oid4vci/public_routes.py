"""Public routes for OID4VCI."""

import datetime
import logging
from secrets import token_urlsafe
from typing import Optional
import uuid

from aiohttp import web
from aiohttp_apispec import docs, form_schema, request_schema, response_schema
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.profile import Profile, ProfileSession
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.wallet.base import BaseWallet, WalletError
from aries_cloudagent.wallet.did_method import KEY
from aries_cloudagent.wallet.error import WalletNotFoundError
from aries_cloudagent.wallet.jwt import JWTVerifyResult, jwt_sign, jwt_verify
from aries_cloudagent.wallet.key_type import ED25519
import jwt
from marshmallow import fields

from .config import Config
from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential

LOGGER = logging.getLogger(__name__)
PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
NONCE_BYTES = 16
EXPIRES_IN = 86400


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
        metadata={
            "description": "The authorization server endpoint. Currently ignored."
        },
    )
    batch_credential_endpoint = fields.Str(
        required=False,
        metadata={"description": "The batch credential endpoint. Currently ignored."},
    )


@docs(tags=["oid4vci"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint."""
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

    metadata = {
        "credential_issuer": f"{public_url}/",
        "credential_endpoint": f"{public_url}/credential",
        "credentials_supported": [
            supported.to_issuer_metadata() for supported in credentials_supported
        ],
    }

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


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre_authorized codes for access tokens."""
    context: AdminRequestContext = request["context"]
    form = await request.post()
    LOGGER.debug(f"Token request: {form}")
    if (grant_type := form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        raise web.HTTPBadRequest(reason=f"grant_type {grant_type} not supported")

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
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=EXPIRES_IN),
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

    jwt_header = jwt.get_unverified_header(cred)
    if "did:key:" not in jwt_header["kid"]:
        raise web.HTTPUnauthorized()  # Invalid authentication credentials

    result = await jwt_verify(profile, cred)
    if not result.valid:
        raise web.HTTPUnauthorized()  # Invalid credentials

    if result.payload["exp"] < datetime.datetime.utcnow():
        raise web.HTTPUnauthorized()  # Token expired

    return result


def filter_subjects(types, subjects, claims):  # -> dict[Any, Any]:
    """Filters subjects only to supported ones."""
    attributes = set()
    for _type in types:
        attributes.update(claims[_type])
    return {key: value for (key, value) in subjects.items() if key in attributes}


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


@docs(tags=["oid4vci"], summary="Issue a credential")
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
            header = jwt.get_unverified_header(proof["jwt"])
            kid = header.get("kid")
            # TODO verify proof
            decoded_payload = jwt.decode(
                proof["jwt"], options={"verify_signature": False}
            )
            if ex_record.nonce != decoded_payload.get("nonce"):
                raise web.HTTPBadRequest(
                    reason="Invalid proof: wrong nonce.",
                )
            # cleanup
            # TODO: cleanup exchange record, possible replay attack
        except jwt.DecodeError:
            print("Error decoding JWT. Invalid token or format.")

    payload = {
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


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/.well-known/openid-credential-issuer",
                credential_issuer_metadata,
                allow_head=False,
            ),
            web.post("/token", token),
            web.post("/credential", issue_cred),
        ]
    )
