"""Back-channel pre-authorized code redemption (admin API).

An external authorization server that serves the wallet-facing pre-authorized
code token request (Keycloak with the OID4VCI extension) calls this endpoint to
redeem a plugin-issued code. The plugin keeps ownership of the code, the
``tx_code`` and the exchange; the authorization server handles wallet
authentication and DPoP, and issues the access token.

This is a trusted backend function, so it lives on the admin port, not the
public OID4VCI port: ``POST /oid4vci/pre-auth/redeem``.

It deliberately does not use ACA-Py admin credentials (API key / tenant
token): the authorization server is an OAuth client of the plugin and
authenticates with the method configured for it in the tenant's authorization
server entry (``private_key_jwt`` by default; see
``auth_providers/client_auth.py``), carried in the form body.

The tenant is carried in that authentication: the caller names the credential
issuer it acts for (``credential_issuer``, a claim of its signed client
assertion, or a form parameter with ``client_secret_post``). The plugin maps it
to the base wallet or a tenant, then verifies the credentials against *that*
tenant's configuration and checks the verified claim matches. A caller cannot
act for a tenant whose configuration doesn't trust it, and no tenant can
redirect another tenant's authorization server to itself.

When the wallet's token request carried ``authorization_details`` (RFC 9396,
OID4VCI 1.0 §5.1.1), the authorization server passes the requested credential
configuration ids; they are checked against the offer before the code is
redeemed, so a mismatch doesn't consume the code.
"""

import json
import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.models.wallet_record import WalletRecord
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, form_schema, response_schema
from marshmallow import fields

from ..auth_providers import (
    AuthServerConfigError,
    BackChannelAuthError,
    resolve_auth_provider,
)
from ..auth_providers.client_auth import CREDENTIAL_ISSUER_CLAIM
from ..config import Config
from ..jose_util import JoseError, unverified_claims
from ..models.supported_cred import SupportedCredential
from ..oauth_errors import oauth_error_response
from ..pre_auth import PreAuthCodeError, lookup_pre_auth_code, redeem_pre_auth_code

LOGGER = logging.getLogger(__name__)

# Suggested lifetime (seconds) of the access token the AS issues for a
# redeemed code. Only needs to cover the nonce + credential requests.
REDEEMED_TOKEN_LIFETIME = 300

# Form parameter: JSON array of the credential configuration ids the wallet
# requested in authorization_details.
REQUESTED_IDS_PARAM = "credential_configuration_ids"
INVALID_AUTHORIZATION_DETAILS = "invalid_authorization_details"


class _UnknownTenant(Exception):
    """The credential issuer named by the caller is not served here."""


def _requested_configuration_ids(params: dict[str, str]) -> list[str] | None:
    """Credential configuration ids requested in authorization_details, if any."""
    raw = params.get(REQUESTED_IDS_PARAM)
    if raw is None:
        return None
    try:
        ids = json.loads(raw)
    except ValueError:
        ids = None
    if not (isinstance(ids, list) and ids and all(isinstance(i, str) and i for i in ids)):
        raise PreAuthCodeError(
            "invalid_request", f"{REQUESTED_IDS_PARAM} must be a JSON array of strings"
        )
    return ids


def _claimed_credential_issuer(params: dict[str, str]) -> str | None:
    """The credential issuer the caller says it acts for (not yet verified)."""
    from_param = params.get(CREDENTIAL_ISSUER_CLAIM)
    assertion = params.get("client_assertion")
    if not assertion:
        return from_param
    try:
        payload = unverified_claims(assertion)
    except JoseError:
        return None
    from_assertion = payload.get(CREDENTIAL_ISSUER_CLAIM)
    if not isinstance(from_assertion, str):
        return None
    if from_param is not None and from_param != from_assertion:
        return None
    return from_assertion


async def _target_profile(
    context: AdminRequestContext, credential_issuer: str
) -> Profile:
    """Map a credential issuer identifier to the base wallet or a tenant profile.

    ``{endpoint}`` is the base wallet; ``{endpoint}/tenant/{wallet_id}`` a tenant.
    """
    root = context.root_profile or context.profile
    endpoint = Config.from_settings(root.settings).endpoint
    if credential_issuer.rstrip("/") == endpoint:
        return root

    prefix = f"{endpoint}/tenant/"
    wallet_id = (
        credential_issuer[len(prefix) :] if credential_issuer.startswith(prefix) else ""
    )
    manager = root.inject_or(BaseMultitenantManager)
    if not wallet_id or "/" in wallet_id or not manager:
        raise _UnknownTenant(credential_issuer)
    try:
        async with root.session() as session:
            wallet = await WalletRecord.retrieve_by_id(session, wallet_id)
    except (StorageNotFoundError, BaseModelError):
        raise _UnknownTenant(credential_issuer) from None
    if wallet.requires_external_key:
        raise _UnknownTenant(credential_issuer)  # unmanaged: no key to open it
    return await manager.get_wallet_profile(root.context, wallet)


class PreAuthRedeemRequestSchema(OpenAPISchema):
    """Form parameters of a redeem request.

    All optional at the schema level so that missing values produce OAuth
    errors from the handler (401 ``invalid_client`` / 400 ``invalid_request``)
    rather than a 422 from request validation.
    """

    pre_authorized_code = fields.Str(
        required=False, metadata={"description": "The pre-authorized code to redeem"}
    )
    tx_code = fields.Str(
        required=False, metadata={"description": "Transaction code entered by the user"}
    )
    wallet_client_id = fields.Str(
        required=False,
        metadata={"description": "The wallet's client_id at the authorization server"},
    )
    credential_configuration_ids = fields.Str(
        required=False,
        metadata={
            "description": "JSON array of the credential configuration ids the "
            "wallet requested in authorization_details; checked against the offer "
            "before the code is redeemed",
            "example": '["org.iso.18013.5.1.mDL"]',
        },
    )
    credential_issuer = fields.Str(
        required=False,
        metadata={
            "description": "Credential issuer (tenant) the caller acts for; required "
            "with client_secret_post, otherwise taken from the client assertion",
            "example": "https://issuer.example.com/tenant/<wallet_id>",
        },
    )
    client_assertion_type = fields.Str(
        required=False,
        metadata={"example": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
    )
    client_assertion = fields.Str(
        required=False,
        metadata={"description": "private_key_jwt / client_secret_jwt client assertion"},
    )
    client_id = fields.Str(
        required=False, metadata={"description": "client_secret_post client id"}
    )
    client_secret = fields.Str(
        required=False, metadata={"description": "client_secret_post client secret"}
    )


class PreAuthRedeemResponseSchema(OpenAPISchema):
    """Result of a successful redemption."""

    refresh_id = fields.Str(
        required=True,
        metadata={"description": "Exchange reference to put in the access token"},
    )
    credential_configuration_ids = fields.List(
        fields.Str(),
        required=True,
        metadata={"description": "Credential configurations the code grants"},
    )
    expires_in = fields.Int(
        required=True,
        metadata={"description": "Suggested access token lifetime in seconds"},
    )


@docs(
    tags=["oid4vci"],
    summary="Redeem a pre-authorized code (authorization server back channel)",
    description=(
        "Called by an external authorization server (e.g. Keycloak) to redeem a "
        "plugin-issued pre-authorized code. Authenticated by the authorization "
        "server's OAuth client authentication (client_assertion, or client_id + "
        "client_secret), not by admin credentials; the tenant is the one whose "
        "credential issuer the authenticated caller names."
    ),
    # Not protected by the admin API key / tenant token (see module docstring).
    security=[],
)
@form_schema(PreAuthRedeemRequestSchema())
@response_schema(PreAuthRedeemResponseSchema(), 200)
async def redeem_pre_auth_code_route(request: web.Request) -> web.Response:
    """Redeem a pre-authorized code on behalf of the authorization server."""
    context: AdminRequestContext = request["context"]
    form = await request.post()
    params = {k: v for k, v in form.items() if isinstance(v, str)}
    unauthenticated = oauth_error_response(
        "invalid_client", "client authentication failed", 401
    )

    credential_issuer = _claimed_credential_issuer(params)
    if not credential_issuer:
        LOGGER.warning("Rejected pre-auth redeem request: no credential_issuer")
        return unauthenticated
    try:
        profile = await _target_profile(context, credential_issuer)
        async with profile.session() as session:
            provider, ctx = await resolve_auth_provider(session, profile)
    except (_UnknownTenant, AuthServerConfigError) as err:
        LOGGER.warning(
            "Rejected pre-auth redeem request for %s: %s", credential_issuer, err
        )
        return unauthenticated
    if not provider.supports_redeem:
        LOGGER.warning(
            "Pre-auth redeem for %s: provider does not redeem", credential_issuer
        )
        return unauthenticated

    try:
        # Verifies the credentials against this tenant's configuration,
        # including that the verified credential_issuer is this tenant's.
        await provider.authenticate_back_channel(
            ctx, params, str(request.url.with_query(None))
        )
    except BackChannelAuthError as err:
        LOGGER.warning("Rejected pre-auth redeem request: %s", err)
        return unauthenticated

    code = params.get("pre_authorized_code") or params.get("pre-authorized_code")
    try:
        requested_ids = _requested_configuration_ids(params)
        # What the code grants, read before redeeming so that a request for
        # another credential configuration doesn't consume the code.
        offered = await lookup_pre_auth_code(profile, code)
    except PreAuthCodeError as err:
        return oauth_error_response(err.error, err.description)
    try:
        async with profile.session() as session:
            supported = await SupportedCredential.retrieve_by_id(
                session, offered.supported_cred_id
            )
    except (StorageError, BaseModelError):
        LOGGER.error("Supported credential for exchange %s missing", offered.exchange_id)
        return oauth_error_response(
            "server_error", "credential configuration not found", 500
        )
    if requested_ids and set(requested_ids) != {supported.identifier}:
        LOGGER.info(
            "Pre-auth redeem for exchange %s: requested %s, offer grants %s",
            offered.exchange_id,
            requested_ids,
            supported.identifier,
        )
        return oauth_error_response(
            INVALID_AUTHORIZATION_DETAILS,
            "authorization_details names a credential configuration the offer "
            "does not include",
        )

    try:
        record = await redeem_pre_auth_code(profile, code, params.get("tx_code"))
    except PreAuthCodeError as err:
        return oauth_error_response(err.error, err.description)

    LOGGER.info(
        "Pre-authorized code for exchange %s redeemed (wallet client %s)",
        record.exchange_id,
        params.get("wallet_client_id"),
    )
    return web.json_response(
        {
            "refresh_id": record.refresh_id,
            "credential_configuration_ids": [supported.identifier],
            "expires_in": REDEEMED_TOKEN_LIFETIME,
        },
        headers={"Cache-Control": "no-store"},
    )
