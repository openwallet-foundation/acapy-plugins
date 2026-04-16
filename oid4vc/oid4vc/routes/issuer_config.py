"""Issuer configuration CRUD routes for OID4VCI admin API.

The IssuerConfiguration record stores per-tenant OAuth authorization server
details (public_url, private_url, auth_type, client_credentials) that the
issuer uses to communicate with the auth server.  It is keyed by wallet_id.
"""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema

from ..models.issuer_config import IssuerConfiguration, IssuerConfigurationSchema
from ..utils import get_wallet_id

LOGGER = logging.getLogger(__name__)


@docs(tags=["oid4vci"], summary="Get issuer configuration")
@response_schema(IssuerConfigurationSchema())
@tenant_authentication
async def get_issuer_configuration(request: web.Request) -> web.Response:
    """Return the IssuerConfiguration for the current wallet."""
    context: AdminRequestContext = request["context"]
    wallet_id = get_wallet_id(context.profile)
    try:
        async with context.session() as session:
            record = await IssuerConfiguration.retrieve_by_id(session, wallet_id)
        return web.json_response(record.serialize())
    except StorageNotFoundError:
        return web.json_response({}, status=200)
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err


@docs(tags=["oid4vci"], summary="Create or update issuer configuration")
@request_schema(IssuerConfigurationSchema())
@response_schema(IssuerConfigurationSchema())
@tenant_authentication
async def put_issuer_configuration(request: web.Request) -> web.Response:
    """Upsert the IssuerConfiguration for the current wallet.

    Uses wallet_id as the record ID so there is exactly one configuration
    record per tenant.
    """
    context: AdminRequestContext = request["context"]
    wallet_id = get_wallet_id(context.profile)
    body = await request.json()

    try:
        async with context.session() as session:
            try:
                record = await IssuerConfiguration.retrieve_by_id(session, wallet_id)
                # Update existing record fields
                for field in IssuerConfiguration.ISSUER_ATTRS:
                    if field in body:
                        setattr(record, field, body[field])
                await record.save(session, reason="Updated issuer configuration")
            except StorageNotFoundError:
                # Create new record with wallet_id as the primary key
                record = IssuerConfiguration(
                    configuration_id=wallet_id,
                    new_with_id=True,
                    **{
                        field: body[field]
                        for field in IssuerConfiguration.ISSUER_ATTRS
                        if field in body
                    },
                )
                await record.save(session, reason="Created issuer configuration")
        return web.json_response(record.serialize())
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
