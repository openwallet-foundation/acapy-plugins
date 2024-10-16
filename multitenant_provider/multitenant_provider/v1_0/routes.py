"""Multitenant provider plugin routes."""

import logging

from acapy_agent.admin.decorators.auth import admin_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.multitenant.admin.routes import (
    CreateWalletRequestSchema,
    CreateWalletResponseSchema,
    CreateWalletTokenRequestSchema,
    CreateWalletTokenResponseSchema,
    wallet_create,
)
from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.multitenant.error import WalletKeyMissingError
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.models.wallet_record import WalletRecord
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import ValidationError, validates_schema

from .config import MultitenantProviderConfig
from .manager import WalletKeyMismatchError

LOGGER = logging.getLogger(__name__)


class PluginCreateWalletRequestSchema(CreateWalletRequestSchema):
    """Request schema for adding a new wallet which will be registered by the agent."""

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields.

        Args:
            data: The data to validate
            kwargs: Additional keyword arguments

        Raises:
            ValidationError: If any of the fields do not validate

        """

        if data.get("wallet_type") in ["indy", "askar"]:
            for field in ("wallet_key", "wallet_name"):
                if field not in data:
                    raise ValidationError("Missing required field", field)


@docs(
    tags=["multitenancy"],
    summary="Create a subwallet (multitenant_provider plugin override)",
)
@request_schema(PluginCreateWalletRequestSchema)
@response_schema(CreateWalletResponseSchema(), 200, description="")
@admin_authentication
async def plugin_wallet_create(request: web.BaseRequest):
    """Request handler for adding a new subwallet for handling by the agent.

    Args:
        request: aiohttp request object
    """

    # we are just overriding the validation (expect askar to have a
    # wallet_name and wallet key) so use the existing create_wallet call
    return await wallet_create(request)


@docs(
    tags=["multitenancy"],
    summary="Get auth token for a subwallet (multitenant_provider plugin override)",
)
@request_schema(CreateWalletTokenRequestSchema)
@response_schema(CreateWalletTokenResponseSchema(), 200, description="")
@admin_authentication
async def plugin_wallet_create_token(request: web.BaseRequest):
    """Request handler for creating an authorization token for a specific subwallet.

    Args:
        request: aiohttp request object
    """

    context: AdminRequestContext = request["context"]
    wallet_id = request.match_info["wallet_id"]
    wallet_key = None

    LOGGER.debug(f"wallet_id = {wallet_id}")

    # "builtin" wallet_create_token uses request.has_body / can_read_body
    # which do not always return true, so wallet_key wasn't getting set or passed
    # into create_auth_token.

    # if there's no body or the wallet_key is not in the body,
    # or wallet_key is blank, return an error
    if not request.body_exists:
        raise web.HTTPUnauthorized(reason="Missing wallet_key")

    body = await request.json()
    wallet_key = body.get("wallet_key")
    LOGGER.debug(f"wallet_key = {wallet_key}")

    # If wallet_key is not there or blank return an error
    if not wallet_key:
        raise web.HTTPUnauthorized(reason="Missing wallet_key")

    profile = context.profile
    config = profile.inject(MultitenantProviderConfig)
    try:
        multitenant_mgr = profile.inject(BaseMultitenantManager)
        async with profile.session() as session:
            wallet_record = await WalletRecord.retrieve_by_id(session, wallet_id)

        # this logic is weird, a managed wallet cannot pass in a key. ! guess
        # this means that a controller determines who can call this endpoint? and
        # there is some other way of ensuring the caller is using the correct wallet_id?
        if (not wallet_record.requires_external_key) and wallet_key:
            if config.errors.on_unneeded_wallet_key:
                raise web.HTTPBadRequest(
                    reason=f"Wallet {wallet_id} doesn't require the wallet key to be provided"  # noqa: E501
                )
            else:
                LOGGER.warning(
                    f"Wallet {wallet_id} doesn't require the wallet key but one was provided"  # noqa: E501
                )

        if not config.manager.always_check_provided_wallet_key:
            # if passed in, remove this wallet key from create auth token logic
            # since we are not going to check it.
            wallet_key = None

        token = await multitenant_mgr.create_auth_token(wallet_record, wallet_key)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except WalletKeyMissingError as err:
        raise web.HTTPUnauthorized(reason=err.roll_up) from err
    except WalletKeyMismatchError as err:
        raise web.HTTPConflict(reason=err.roll_up) from err

    return web.json_response({"token": token})


async def register(app: web.Application):
    """Register routes."""
    LOGGER.info("> registering routes")

    # we need to replace the current multitenant endpoints...
    # 1) to enforce validation on askar wallets
    has_wallet_create = False
    # 2) and to ensure that we can pass along and check the wallet key
    has_wallet_create_token = False
    for r in app.router.routes():
        if r.method == "POST":
            if r.resource and r.resource.canonical == "/multitenancy/wallet":
                LOGGER.info(
                    f"found route: {r.method} {r.resource.canonical} ({r.handler})"
                )
                LOGGER.info(f"... replacing current handler: {r.handler}")
                r._handler = plugin_wallet_create
                LOGGER.info(f"... with new handler: {r.handler}")
                has_wallet_create = True
            if (
                r.resource
                and r.resource.canonical == "/multitenancy/wallet/{wallet_id}/token"
            ):
                LOGGER.info(
                    f"found route: {r.method} {r.resource.canonical} ({r.handler})"
                )
                LOGGER.info(f"... replacing current handler: {r.handler}")
                r._handler = plugin_wallet_create_token
                LOGGER.info(f"... with new handler: {r.handler}")
                has_wallet_create_token = True

    # ok, just in case we get loaded before the builtin multitenant (should be impossible)
    # let's make sure we've added endpoints we expect
    if not has_wallet_create:
        LOGGER.info("adding POST /multitenancy/wallet route")
        app.add_routes(
            [
                web.post("/multitenancy/wallet", plugin_wallet_create),
            ]
        )
    if not has_wallet_create_token:
        LOGGER.info("adding POST /multitenancy/wallet/<wallet_id>/token route")
        app.add_routes(
            [
                web.post(
                    "/multitenancy/wallet/{wallet_id}/token", plugin_wallet_create_token
                ),
            ]
        )

    LOGGER.info("< registering routes")


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {"name": "multitenancy", "description": "Multitenant wallet management"}
    )
