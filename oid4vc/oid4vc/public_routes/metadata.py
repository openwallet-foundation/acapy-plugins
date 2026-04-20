"""Credential issuer metadata endpoint for OID4VCI."""

import json
import logging
import time
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, response_schema
from marshmallow import fields

from ..config import Config
from ..cred_processor import CredProcessors
from ..did_utils import retrieve_or_create_did_jwk
from ..jwt import jwt_sign
from ..models.supported_cred import SupportedCredential
from ..utils import get_first_auth_server

LOGGER = logging.getLogger(__name__)


class BatchCredentialIssuanceSchema(OpenAPISchema):
    """Batch credential issuance schema."""

    batch_size = fields.Int(
        required=True, metadata={"description": "The maximum array size for the proofs"}
    )


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={"description": "The credential issuer endpoint."},
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "The authorization server endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={"description": "The credential endpoint."},
    )
    nonce_endpoint = fields.Str(
        required=False,
        metadata={"description": "The nonce endpoint."},
    )
    credential_configurations_supported = fields.List(
        fields.Dict(),
        metadata={"description": "The supported credentials."},
    )
    batch_credential_issuance = fields.Nested(
        BatchCredentialIssuanceSchema,
        required=False,
        metadata={"description": "The batch credential issuance. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint.

    If the client sends `Accept: application/jwt`, the metadata is returned as
    a signed JWT (OID4VCI 1.0 §11.2.2 — signed metadata).  Otherwise, plain
    JSON is returned.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)
        auth_server = await get_first_auth_server(session, context.profile)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        metadata: dict[str, Any] = {"credential_issuer": f"{public_url}{subpath}"}
        if auth_server:
            # Point directly at the auth server's public URL so the wallet
            # performs OAuth discovery and token requests against the auth server.
            metadata["authorization_servers"] = [auth_server["public_url"]]
        else:
            # When ACA-Py is its own authorization server (no external auth server),
            # include token_endpoint directly in the credential issuer metadata.
            # This is technically an extension beyond OID4VCI spec §11.2.1 (which
            # says token_endpoint belongs in AS metadata via /.well-known/oauth-
            # authorization-server), but some wallets (e.g. waltid) read
            # token_endpoint from resolveCIProviderMetadata() and NPE if absent,
            # rather than performing AS discovery.
            metadata["token_endpoint"] = f"{public_url}{subpath}/token"
        metadata["credential_endpoint"] = f"{public_url}{subpath}/credential"
        metadata["notification_endpoint"] = f"{public_url}{subpath}/notification"
        metadata["nonce_endpoint"] = f"{public_url}{subpath}/nonce"
        processors = context.inject(CredProcessors)
        cred_configs = {}
        for supported in credentials_supported:
            try:
                issuer = processors.issuer_for_format(supported.format)
            except Exception:
                issuer = None
            cred_configs[supported.identifier] = supported.to_issuer_metadata(
                issuer=issuer
            )
        metadata["credential_configurations_supported"] = cred_configs

        # OID4VCI 1.0 §11.2.2: if client requests signed metadata, sign and return
        # the metadata document as a JWT with Content-Type: application/jwt.
        accept = request.headers.get("Accept", "")
        vm: str | None = None
        jwk_public: dict | None = None
        if "application/jwt" in accept:
            try:
                async with context.profile.session() as sig_session:
                    jwk_info = await retrieve_or_create_did_jwk(sig_session)
                vm = f"{jwk_info.did}#0"
                # Decode the public JWK from the did:jwk DID.
                # did:jwk:<base64url(jwk_json)> — reverse _create_default_did.
                jwk_encoded = jwk_info.did[len("did:jwk:") :]
                jwk_public = json.loads(b64_to_bytes(jwk_encoded, urlsafe=True).decode())
            except (WalletNotFoundError, WalletError, AssertionError) as err:
                LOGGER.warning("Cannot sign metadata JWT: %s", err)

    if "application/jwt" in accept and vm and jwk_public:
        # Build JWT payload: include all metadata fields + required JWT claims
        issuer_url = f"{public_url}{subpath}"
        payload = {
            **metadata,
            "iss": issuer_url,
            "sub": issuer_url,
            "iat": int(time.time()),
        }
        try:
            signed_jwt = await jwt_sign(
                context.profile,
                # Include the public JWK in the header — OID4VCI §11.2.2 / RFC 7515
                # requires either `jwk` or `x5c` for signed issuer metadata.
                # The `jwk` must have `kid` matching the JWT header's `kid` so
                # the conformance suite can locate the correct key.
                headers={
                    "jwk": {**jwk_public, "kid": vm},
                    "typ": "openid-credential-issuer",
                },
                payload=payload,
                verification_method=vm,
            )
        except (WalletNotFoundError, WalletError) as err:
            LOGGER.warning("Cannot sign metadata JWT: %s", err)
            return web.json_response(metadata)

        LOGGER.debug("SIGNED METADATA JWT: %s", signed_jwt[:60])
        return web.Response(
            body=signed_jwt,
            content_type="application/jwt",
        )

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)


@docs(tags=["oid4vc"], summary="OpenID Connect Discovery with OID4VCI")
async def openid_configuration(request: web.Request):
    """OpenID Connect Discovery endpoint with OID4VCI compatibility.

    Returns combined OpenID Connect Discovery 1.0 metadata and OID4VCI
    credential issuer metadata for maximum interoperability.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)
        auth_server = await get_first_auth_server(session, context.profile)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        base_url = f"{public_url}{subpath}"

        processors = context.inject(CredProcessors)
        cred_configs = {}
        for supported in credentials_supported:
            try:
                issuer = processors.issuer_for_format(supported.format)
            except Exception:
                issuer = None
            cred_configs[supported.identifier] = supported.to_issuer_metadata(
                issuer=issuer
            )

        # Combined OIDC Discovery + OID4VCI metadata
        metadata: dict[str, Any] = {
            # OIDC Discovery fields (RFC 8414 / OIDC Discovery required fields)
            "issuer": base_url,
            # authorization_endpoint is required by CheckServerConfiguration in the
            # OIDF conformance suite (condition.common.CheckServerConfiguration checks
            # for "authorization_endpoint", "token_endpoint", and "issuer").
            # For pre-authorized_code flow the authorization endpoint is not invoked,
            # but it must be advertised in the AS metadata.
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "response_types_supported": ["code"],
            # DPoP support - required by HAIP profile (DPOP-5.1).
            # Advertise the algorithms supported for DPoP proof JWTs.
            "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512"],
            # OAuth 2.0 AS Metadata fields
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            # RFC 9396 Rich Authorization Requests — advertise the authorization_details
            # type(s) supported (required by OID4VCI HAIP AS metadata validation).
            "authorization_details_types_supported": ["openid_credential"],
            # OID4VCI fields
            "credential_issuer": base_url,
            "credential_endpoint": f"{base_url}/credential",
            "notification_endpoint": f"{base_url}/notification",
            # OID4VCI nonce endpoint for server-generated nonces (HAIP required).
            # Wallets call this before building a credential proof to get a fresh
            # nonce that ACA-Py validates in the JWT proof `nonce` claim.
            "nonce_endpoint": f"{base_url}/nonce",
            "credential_configurations_supported": cred_configs,
        }

        if auth_server:
            metadata["authorization_servers"] = [auth_server["public_url"]]

    LOGGER.debug("OPENID CONFIG: %s", metadata)

    return web.json_response(metadata)
