"""Credential issuer metadata endpoint for OID4VCI."""

import json
import logging
import time
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, response_schema
from marshmallow import fields

from ..config import Config
from ..cred_processor import CredProcessors
from ..did_utils import retrieve_or_create_did_jwk
from ..jwt import jwt_sign
from ..models.issuer_config import IssuerConfiguration
from ..models.supported_cred import SupportedCredential

LOGGER = logging.getLogger(__name__)


async def _load_issuer_context(session, wallet_id: str | None):
    """Load IssuerConfiguration and the first AS entry with a public_url."""
    try:
        cfg = await IssuerConfiguration.retrieve_by_id(
            session, wallet_id or "default-wallet"
        )
    except StorageNotFoundError:
        cfg = None
    servers = (cfg.authorization_servers if cfg else None) or []
    auth = next((a for a in servers if a.get("public_url")), None)
    return cfg, auth


def _build_cred_configs(credentials_supported, processors) -> dict:
    """Build the credential_configurations_supported map."""
    result: dict = {}
    for supported in credentials_supported:
        try:
            issuer = processors.issuer_for_format(supported.format)
        except Exception:
            issuer = None
        result[supported.identifier] = supported.to_issuer_metadata(issuer=issuer)
    return result


def _apply_overlay(
    metadata: dict, issuer_config, cred_configs: dict, base_url: str, enable_nonce: bool
) -> None:
    """Overlay DB config (keeping server-derived cred_configs) and gate nonce_endpoint."""
    if issuer_config:
        metadata.update(issuer_config.issuer_metadata(base_url))
        metadata["credential_configurations_supported"] = cred_configs
    if enable_nonce:
        metadata.setdefault("nonce_endpoint", f"{base_url}/nonce")
    else:
        metadata.pop("nonce_endpoint", None)


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
    credential_configurations_supported = fields.Dict(
        keys=fields.Str(),
        values=fields.Dict(),
        required=True,
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
    a signed JWT (OID4VCI 1.0 §12.2.2 — metadata retrieval; §12.2.3 defines
    the signed metadata format). Otherwise, plain JSON is returned.
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        # TODO If there's a lot, this will be a problem
        credentials_supported = await SupportedCredential.query(session)

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        issuer_config, auth_server = await _load_issuer_context(session, wallet_id)

        metadata: dict[str, Any] = {"credential_issuer": f"{public_url}{subpath}"}
        if auth_server:
            metadata["authorization_servers"] = [auth_server["public_url"]]
        else:
            # Extension for wallets (e.g. waltid) that read token_endpoint from
            # credential issuer metadata instead of doing AS discovery.
            metadata["token_endpoint"] = f"{public_url}{subpath}/token"
        metadata["credential_endpoint"] = f"{public_url}{subpath}/credential"
        metadata["notification_endpoint"] = f"{public_url}{subpath}/notification"
        cred_configs = _build_cred_configs(
            credentials_supported, context.inject(CredProcessors)
        )
        metadata["credential_configurations_supported"] = cred_configs

        _apply_overlay(
            metadata,
            issuer_config,
            cred_configs,
            f"{public_url}{subpath}",
            config.enable_nonce_endpoint,
        )

        # OID4VCI 1.0 §12.2.2/§12.2.3: signed metadata as JWT with application/jwt.
        accept = request.headers.get("Accept", "")
        vm: str | None = None
        jwk_public: dict | None = None
        if "application/jwt" in accept:
            try:
                async with context.profile.session() as sig_session:
                    jwk_info = await retrieve_or_create_did_jwk(sig_session)
                vm = f"{jwk_info.did}#0"
                # did:jwk:<base64url(jwk_json)> — reverse _create_default_did.
                jwk_encoded = jwk_info.did[len("did:jwk:") :]
                jwk_public = json.loads(b64_to_bytes(jwk_encoded, urlsafe=True).decode())
            except (WalletNotFoundError, WalletError, AssertionError) as err:
                LOGGER.warning("Cannot sign metadata JWT: %s", err)

    if "application/jwt" in accept and vm and jwk_public:
        # §12.2.3: `sub` MUST match the Credential Issuer Identifier — use the
        # value in metadata so a DB-overridden credential_issuer is honored.
        issuer_url = metadata["credential_issuer"]
        payload = {
            **metadata,
            "iss": issuer_url,
            "sub": issuer_url,
            "iat": int(time.time()),
        }
        try:
            signed_jwt = await jwt_sign(
                context.profile,
                # OID4VCI §12.2.3 requires typ=openidvci-issuer-metadata+jwt.
                # `jwk` in the header conveys the key (RFC 7515 §4.1.3).
                headers={
                    "jwk": {**jwk_public, "kid": vm},
                    "typ": "openidvci-issuer-metadata+jwt",
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

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        base_url = f"{public_url}{subpath}"
        issuer_config, auth_server = await _load_issuer_context(session, wallet_id)

        cred_configs = _build_cred_configs(
            credentials_supported, context.inject(CredProcessors)
        )

        metadata: dict[str, Any] = {
            "issuer": base_url,
            # Required by OIDF CheckServerConfiguration; unused in pre-auth flow.
            "authorization_endpoint": f"{base_url}/authorize",
            "response_types_supported": ["code"],
            "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512"],
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "authorization_details_types_supported": ["openid_credential"],
            "credential_issuer": base_url,
            "credential_endpoint": f"{base_url}/credential",
            "notification_endpoint": f"{base_url}/notification",
            "credential_configurations_supported": cred_configs,
        }

        # token_endpoint belongs to the AS; only advertise when ACA-Py is its own AS.
        if not auth_server:
            metadata["token_endpoint"] = f"{base_url}/token"

        if auth_server:
            metadata["authorization_servers"] = [auth_server["public_url"]]

        _apply_overlay(
            metadata, issuer_config, cred_configs, base_url, config.enable_nonce_endpoint
        )

    LOGGER.debug("OPENID CONFIG: %s", metadata)

    return web.json_response(metadata)
