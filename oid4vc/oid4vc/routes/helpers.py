"""Helper functions for OID4VC routes."""

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError
from aiohttp import web

from ..auth_providers import AuthServerConfigError, resolve_auth_provider
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential


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
            if record.state == OID4VCIExchangeRecord.STATE_CREATED:
                provider, ctx = await resolve_auth_provider(session, context.profile)
                record.code = await provider.create_pre_authorized_code(
                    ctx,
                    subject_id=record.refresh_id,
                    credential_configuration_id=supported.identifier,
                    user_pin=record.pin,
                )
                record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
                await record.save(session, reason="Credential offer created")
            elif record.state != OID4VCIExchangeRecord.STATE_OFFER_CREATED:
                raise web.HTTPBadRequest(
                    reason="This exchange record has already been used."
                )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except AuthServerConfigError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

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
