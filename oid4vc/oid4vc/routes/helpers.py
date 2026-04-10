"""Helper functions for OID4VC routes."""

import secrets

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError
from aiohttp import web

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential
from ..utils import get_auth_header, get_auth_server_url, get_first_auth_server, get_tenant_subpath

CODE_BYTES = 32


async def _create_pre_auth_code(
    profile: Profile,
    config: Config,
    auth_server: dict | None,
    subject_id: str,
    credential_configuration_id: str | None = None,
    user_pin: str | None = None,
) -> str:
    """Create a secure random pre-authorized code."""

    if auth_server:
        private_url = get_auth_server_url(auth_server)
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"

        grants_endpoint = f"{private_url}/grants/pre-authorized-code"

        auth_header = await get_auth_header(
            profile, auth_server, issuer_server_url, grants_endpoint
        )
        user_pin_required = user_pin is not None
        resp = await AppResources.get_http_client().post(
            grants_endpoint,
            json={
                "subject_id": subject_id,
                "user_pin_required": user_pin_required,
                "user_pin": user_pin,
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "credential_configuration_id": credential_configuration_id,
                    }
                ],
            },
            headers={"Authorization": f"{auth_header}"},
        )
        if resp.status != 200:
            body = await resp.text()
            raise web.HTTPBadGateway(
                reason=f"Auth server returned {resp.status}: {body}"
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
            auth_server = await get_first_auth_server(session, context.profile)
            record.code = await _create_pre_auth_code(
                context.profile,
                config,
                auth_server,
                record.refresh_id,
                supported.identifier,
                record.pin,
            )
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    user_pin_required: bool = record.pin is not None
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    pre_auth_grant: dict = {
        "pre-authorized_code": record.code,
    }
    if user_pin_required:
        # OID4VCI 1.0 final: tx_code replaces user_pin_required in the offer.
        # Indicate that a transaction code is required without revealing the value.
        pre_auth_grant["tx_code"] = {"input_mode": "text"}
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credential_configuration_ids": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": pre_auth_grant,
        },
    }
