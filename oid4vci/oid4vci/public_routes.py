"""Public routes for OID4VCI."""

import datetime
import logging
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional

import jwt
from aiohttp import web
from aiohttp_apispec import docs, form_schema, request_schema, response_schema
from aries_askar import Key, KeyAlg
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.resolver.did_resolver import DIDResolver
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.utils.classloader import ClassLoader, ModuleLoadError
from aries_cloudagent.wallet.base import WalletError
from aries_cloudagent.wallet.error import WalletNotFoundError
from aries_cloudagent.wallet.jwt import (
    JWTVerifyResult,
    b64_to_dict,
    jwt_sign,
    jwt_verify,
)
from aries_cloudagent.wallet.util import b58_to_bytes, b64_to_bytes
from marshmallow import fields
from pydid import DIDUrl

from .config import Config
from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult
from .cred_processor import CredIssueError

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
        "exp": (
            datetime.datetime.utcnow() + datetime.timedelta(seconds=EXPIRES_IN)
        ).timestamp(),
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

    if result.payload["exp"] < datetime.datetime.utcnow().timestamp():
        raise web.HTTPUnauthorized()  # Token expired

    return result


async def key_material_for_kid(profile: Profile, kid: str):
    """Resolve key material for a kid."""
    try:
        DIDUrl(kid)
    except ValueError as exc:
        raise web.HTTPBadRequest(reason="Invalid kid; DID URL expected") from exc

    resolver = profile.inject(DIDResolver)
    vm = await resolver.dereference_verification_method(profile, kid)
    if vm.type == "JsonWebKey2020" and vm.public_key_jwk:
        return Key.from_jwk(vm.public_key_jwk)
    if vm.type == "Ed25519VerificationKey2018" and vm.public_key_base58:
        key_bytes = b58_to_bytes(vm.public_key_base58)
        return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)
    if vm.type == "Ed25519VerificationKey2020" and vm.public_key_multibase:
        key_bytes = b58_to_bytes(vm.public_key_multibase[1:])
        if len(key_bytes) == 32:
            pass
        elif len(key_bytes) == 34:
            # Trim off the multicodec header, if present
            key_bytes = key_bytes[2:]
        return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)

    raise web.HTTPBadRequest(reason="Unsupported verification method type")


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], nonce: str
):
    """Handle proof of posession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    if headers.get("typ") != "openid4vci-proof+jwt":
        raise web.HTTPBadRequest(reason="Invalid proof: wrong typ.")

    if "kid" in headers:
        key = await key_material_for_kid(profile, headers["kid"])
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
    body = await request.json()
    LOGGER.info(f"request: {body}")
    try:
        async with context.profile.session() as session:
            ex_record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, ex_record.supported_cred_id
            )
        config = Config.from_settings(context.settings)
        handler_name = config.cred_handler[supported.format]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if ex_record.nonce is None:
        raise web.HTTPBadRequest(
            reason="Invalid exchange; no offer created for this request"
        )

    if supported.format != body.get("format"):
        raise web.HTTPBadRequest(reason="Requested format does not match offer.")

    if handler_name is None:
        raise web.HTTPUnprocessableEntity(reason=f"{supported.format} is supported.")

    if supported.format_data is None:
        LOGGER.error(f"No format_data for supported credential {supported.format}.")
        raise web.HTTPInternalServerError()

    if "proof" not in body:
        raise web.HTTPBadRequest(reason=f"proof is required for {supported.format}")

    pop = await handle_proof_of_posession(
        context.profile, body["proof"], ex_record.nonce
    )
    if not pop.verified:
        raise web.HTTPBadRequest(reason="Invalid proof")

    try:
        handler = ClassLoader.load_module(handler_name)
        LOGGER.debug(f"Loaded module: {handler_name}")
    except ModuleLoadError as e:
        LOGGER.error(f"Error loading handler module: {e}")
        raise web.HTTPInternalServerError(
            reason=f"No handler to process {supported.format} credential."
        )

    try:
        credential = await handler.cred_processor.issue_cred(
            body, supported, ex_record, pop, context
        )
    except CredIssueError as e:
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


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/.well-known/openid-credential-issuer",
                credential_issuer_metadata,
                allow_head=False,
            ),
            # TODO Add .well-known/did-configuration.json
            # Spec: https://identity.foundation/.well-known/resources/did-configuration/
            web.post("/token", token),
            web.post("/credential", issue_cred),
        ]
    )
