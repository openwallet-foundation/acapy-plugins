"""Admin server classes."""

import logging

from aiohttp import web
from aiohttp_apispec import setup_aiohttp_apispec, validation_middleware
import aiohttp_cors
from aries_cloudagent.admin.base_server import BaseAdminServer
from aries_cloudagent.admin.error import AdminSetupError
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.admin.server import debug_middleware, ready_middleware
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.profile import Profile

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
        """
        self.app = None
        self.host = host
        self.port = port
        self.context = context
        self.profile = root_profile
        self.site = None

    async def make_application(self) -> web.Application:
        """Get the aiohttp application instance."""

        middlewares = [ready_middleware, debug_middleware, validation_middleware]

        @web.middleware
        async def setup_context(request: web.Request, handler):
            """Set up request context.

            TODO: support Multitenancy context setup
            Right now, this will only work for a standard agent instance. To
            support multitenancy, we will need to include wallet identifiers in
            the path and report that path in credential offers and issuer
            metadata from a tenant.
            """
            admin_context = AdminRequestContext(
                profile=self.profile,
                # root_profile=self.profile, # TODO: support Multitenancy context setup
                # metadata={}, # TODO: support Multitenancy context setup
            )
            request["context"] = admin_context
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

        await public_routes_register(app)

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
