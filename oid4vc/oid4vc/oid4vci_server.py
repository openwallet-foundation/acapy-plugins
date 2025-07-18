"""Admin server classes."""

import logging

import aiohttp_cors
from acapy_agent.admin.base_server import BaseAdminServer
from acapy_agent.admin.error import AdminSetupError
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.admin.server import debug_middleware, ready_middleware
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.models.wallet_record import WalletRecord
from acapy_agent.storage.error import StorageError
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.multitenant.base import BaseMultitenantManager
from aiohttp import web
from aiohttp_apispec import setup_aiohttp_apispec, validation_middleware

from .public_routes import register as public_routes_register

LOGGER = logging.getLogger(__name__)


class Oid4vciServer(BaseAdminServer):
    """Server for OpenID4VCI routes.

    This server must be separate from the Admin API of ACA-Py because the
    audience is different. ACA-Py's Admin API is meant for internal use only.
    It's endpoints are secured by either API Key or by firewall rules. In contrast,
    the OpenID4VCI routes must be publicly accessible. The authorization for these
    routes are controlled by knowledge of codes and tokens as passed during the
    protocol implemented by the endpoints.

    In addition to the public routes, this server also provides a health check
    """

    def __init__(
        self,
        host: str,
        port: int,
        context: InjectionContext,
        root_profile: Profile,
    ):
        """Initialize an Oid4vciServer instance.

        Args:
            host: Host to listen on
            port: Port to listen on
            context: The application context instance
            root_profile: The root profile instance
        """
        self.app = None
        self.host = host
        self.port = port
        self.context = context
        self.profile = root_profile
        self.site = None
        self.multitenant_manager = context.inject_or(BaseMultitenantManager)

    async def make_application(self) -> web.Application:
        """Get the aiohttp application instance."""

        middlewares = [ready_middleware, debug_middleware, validation_middleware]

        @web.middleware
        async def setup_context(request: web.Request, handler):
            """Set up request context.

            This middleware is responsible for setting up the request context for the
            handler. If multitenancy is enabled and a wallet_id is provided in the request
            the wallet profile is retrieved and injected into the context.

            Args:
                request (web.Request): The incoming web request.
                handler: The handler function to be executed.

            Returns:
                The result of executing the handler function with the updated request
                context.
            """
            multitenant = self.multitenant_manager
            wallet_id = request.match_info.get("wallet_id")

            if multitenant and wallet_id:
                try:
                    async with self.profile.session() as session:
                        wallet_record = await WalletRecord.retrieve_by_id(
                            session, wallet_id
                        )
                except (StorageError, BaseModelError) as err:
                    raise web.HTTPBadRequest(reason=err.roll_up) from err
                wallet_info = wallet_record.serialize()
                wallet_key = wallet_info["settings"]["wallet.key"]
                _, wallet_profile = await multitenant.get_wallet_and_profile(
                    self.context, wallet_id, wallet_key
                )
                admin_context = AdminRequestContext(
                    profile=wallet_profile,
                    root_profile=self.profile,
                    metadata={
                        "wallet_id": wallet_id,
                        "wallet_key": wallet_key,
                    },
                )
                request["context"] = admin_context
            else:
                request["context"] = AdminRequestContext(
                    profile=self.profile,
                )
            return await handler(request)

        middlewares.append(setup_context)

        app = web.Application(
            middlewares=middlewares,
            # TODO: Do these values need to be tweaked for OpenID4VCI?
            client_max_size=(
                self.context.settings.get("admin.admin_client_max_request_size", 1)
                * 1024
                * 1024
            ),
        )

        app.add_routes(
            [
                # TODO: No swagger in production?
                web.get("/", self.redirect_handler, allow_head=True),
            ]
        )

        await public_routes_register(app, self.multitenant_manager, self.context)

        cors = aiohttp_cors.setup(
            app,
            defaults={
                "*": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*",
                )
            },
        )
        for route in app.router.routes():
            cors.add(route)

        # get agent label
        __version__ = 0  # TODO: get dynamically from config
        version_string = f"v{__version__}"

        setup_aiohttp_apispec(
            app=app, title="OpenID4VCI", version=version_string, swagger_path="/api/doc"
        )

        # ensure we always have status values
        app._state["ready"] = False
        app._state["alive"] = False

        return app

    async def start(self) -> None:
        """Start the webserver.

        Raises:
            AdminSetupError: If there was an error starting the webserver

        """

        self.app = await self.make_application()
        runner = web.AppRunner(self.app)
        await runner.setup()

        self.site = web.TCPSite(runner, host=self.host, port=self.port)

        try:
            await self.site.start()
            self.app._state["ready"] = True
            self.app._state["alive"] = True
        except OSError:
            raise AdminSetupError(
                "Unable to start webserver with host "
                + f"'{self.host}' and port '{self.port}'\n"
            )

    async def stop(self) -> None:
        """Stop the webserver."""
        self.app._state["ready"] = False  # in case call does not come through OpenAPI
        if self.site:
            await self.site.stop()
            self.site = None

    async def redirect_handler(self, request: web.BaseRequest):
        """Perform redirect to documentation."""
        raise web.HTTPFound("/api/doc")
