"""Credential offer endpoints and helpers."""

import json
import logging
import secrets
from urllib.parse import quote

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    response_schema,
)
from marshmallow import fields

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential
from ..utils import get_auth_header, get_tenant_subpath

LOGGER = logging.getLogger(__name__)
CODE_BYTES = 16


class CredOfferQuerySchema(OpenAPISchema):
    """Schema for GetCredential."""

    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


class CredOfferGrantSchema(OpenAPISchema):
    """Schema for GetCredential."""

    pre_authorized_code = fields.Str(required=True)
    user_pin_required = fields.Bool(required=False)


class CredOfferSchema(OpenAPISchema):
    """Credential Offer Schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential issuer.",
            "example": "https://example.com",
        },
    )
    credentials = fields.List(
        fields.Str(
            required=True,
            metadata={
                "description": "The credential type identifier.",
                "example": "UniversityDegreeCredential",
            },
        )
    )
    grants = fields.Nested(CredOfferGrantSchema(), required=True)


class CredOfferResponseSchemaVal(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer = fields.Str(
        required=True,
        metadata={
            "description": "The URL of the credential value for display by QR code.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)


class CredOfferResponseSchemaRef(OpenAPISchema):
    """Credential Offer Schema."""

    credential_offer_uri = fields.Str(
        required=True,
        metadata={
            "description": "A URL which references the credential for display.",
            "example": "openid-credential-offer://...",
        },
    )
    offer = fields.Nested(CredOfferSchema(), required=True)


async def _create_pre_auth_code(
    profile: Profile,
    config: Config,
    subject_id: str,
    credential_configuration_id: str | None = None,
    user_pin: str | None = None,
) -> str:
    """Create a secure random pre-authorized code."""

    if config.auth_server_url:
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"

        auth_server_url = f"{config.auth_server_url}{get_tenant_subpath(profile)}"
        grants_endpoint = f"{auth_server_url}/grants/pre-authorized-code"

        auth_header = await get_auth_header(
            profile, config, issuer_server_url, grants_endpoint
        )
        resp = await AppResources.get_http_client().post(
            grants_endpoint,
            json={
                "subject_id": subject_id,
                "txt_code": user_pin,
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "credential_configuration_id": credential_configuration_id,
                    }
                ],
            },
            headers={"Authorization": f"{auth_header}"},
        )
        data = await resp.json()
        code = data["pre_authorized_code"]
    else:
        code = secrets.token_urlsafe(CODE_BYTES)
    return code


async def _parse_cred_offer(context: AdminRequestContext, exchange_id: str) -> dict:
    """Helper function for cred_offer request parsing.

    Used in get_cred_offer and public_routes.dereference_cred_offer endpoints.
    """
    config = Config.from_settings(context.settings)
    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
            record.code = await _create_pre_auth_code(
                context.profile,
                config,
                record.refresh_id,
                supported.identifier,
                record.pin,
            )
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    pre_auth_code_grant = {"pre-authorized_code": record.code}
    if record.pin:
        pre_auth_code_grant["tx_code"] = record.pin
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credential_configuration_ids": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": pre_auth_code_grant
        },
    }


@docs(tags=["oid4vci"], summary="Get a credential offer by value")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
@tenant_authentication
async def get_cred_offer(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by value.

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    offer_uri = quote(json.dumps(offer))
    offer_response = {
        "offer": offer,
        "credential_offer": f"openid-credential-offer://?credential_offer={offer_uri}",
    }
    return web.json_response(offer_response)


@docs(tags=["oid4vci"], summary="Get a credential offer by reference")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaRef(), 200)
@tenant_authentication
async def get_cred_offer_by_ref(request: web.BaseRequest):
    """Endpoint to retrieve an OpenID4VCI compliant offer by reference.

    credential_offer_uri can be dereferenced at the /oid4vc/dereference-credential-offer
    (see public_routes.dereference_cred_offer)

    For example, can be used in QR-Code presented to a compliant wallet.
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )

    offer = await _parse_cred_offer(context, exchange_id)

    config = Config.from_settings(context.settings)
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    ref_uri = f"{config.endpoint}{subpath}/oid4vci/dereference-credential-offer"
    offer_response = {
        "offer": offer,
        "credential_offer_uri": f"openid-credential-offer://?credential_offer={quote(ref_uri)}",
    }
    return web.json_response(offer_response)
