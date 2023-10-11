"""Admin server classes."""

import logging
from hmac import compare_digest
import secrets
import string
from typing import Callable, Coroutine

import aiohttp_cors
from aiohttp import web
from aiohttp_apispec import (
    docs,
    response_schema,
    querystring_schema,
    setup_aiohttp_apispec,
    validation_middleware,
)
from aries_cloudagent.admin.base_server import BaseAdminServer
from aries_cloudagent.admin.error import AdminSetupError
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.admin.server import debug_middleware, ready_middleware
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.utils.stats import Collector
from aries_cloudagent.version import __version__
from marshmallow import fields

LOGGER = logging.getLogger(__name__)


class IssueCredentialRequestSchema(OpenAPISchema):
    format = fields.Str(
        required=True,
        metadata= {"description": "The client ID for the token request.", "example": ""}
    )
    types= fields.List(
        fields.Nested(fields.Str()),
        metadata={"description": "List of connection records"},
    )
    credentialsSubject= fields.Dict(
        metadata={"description": ""}
    )
    proof= fields.Dict(
        metadata={"description": ""}
    )

class TokenRequestSchema(OpenAPISchema):
    """Request schema for the /token endpoint."""

    client_id = fields.Str(
        required=True,
        metadata= {"description": "The client ID for the token request.", "example": ""}
    )

    grant_type = fields.Str(
        required=True,
        metadata= {"description": "", "example": ""}
    )

    pre_authorized_code = fields.Str(
        required=True,
        metadata= {"description": "", "example": ""}
    )

class GetCredentialOfferSchema(OpenAPISchema):
    """Schema for GetCredential"""

    credentials = fields.List(fields.Str())
    credential_issuer = fields.Str()
    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


class AdminResetSchema(OpenAPISchema):
    """Schema for the reset endpoint."""


class AdminStatusLivelinessSchema(OpenAPISchema):
    """Schema for the liveliness endpoint."""

    alive = fields.Boolean(
        metadata={"description": "Liveliness status", "example": True}
    )


class AdminStatusReadinessSchema(OpenAPISchema):
    """Schema for the readiness endpoint."""

    ready = fields.Boolean(
        metadata={"description": "Readiness status", "example": True}
    )


class Oid4vciServer(BaseAdminServer):
    """Oid4vci HTTP server class."""

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

        def is_unprotected_path(path: str):
            return path in [
                "/api/doc",
                "/api/docs/swagger.json",
                "/favicon.ico",
                "/status/live",
                "/status/ready",
            ] or path.startswith("/static/swagger/")

        # TODO: repurpose this to check oid4vci jwt tokens ----------
        @web.middleware
        async def check_token(request: web.Request, handler):
            header_admin_api_key = request.headers.get("x-api-key")
            admin_api_key = ""
            valid_key = compare_digest(
                admin_api_key.encode(), header_admin_api_key.encode()
            )

            # We have to allow OPTIONS method access to paths without a key since
            # browsers performing CORS requests will never include the original
            # x-api-key header from the method that triggered the preflight
            # OPTIONS check.
            if (
                valid_key
                # or is_unprotected_path(request.path) # TODO: issue credential endpoint
                or (request.method == "OPTIONS")
            ):
                return await handler(request)
            else:
                raise web.HTTPUnauthorized()

        # middlewares.append(check_token)
        # ----------

        @web.middleware
        async def setup_context(request: web.Request, handler):
            profile = self.profile

            admin_context = AdminRequestContext(
                profile=profile,
                # root_profile=self.profile, # TODO: support Multitenancy context setup
                # metadata={},# TODO: support Multitenancy context setup
            )
            request["context"] = admin_context
            return await handler(request)

        middlewares.append(setup_context)

        app = web.Application(
            middlewares=middlewares,
            client_max_size=(  # TODO: update settings for oid4vci
                self.context.settings.get("admin.admin_client_max_request_size", 1)
                * 1024
                * 1024
            ),
        )

        app.add_routes(
            [
                web.get("/.well-known/openid-credential-issuer", self.oid_cred_issuer),
                # web.get("/.well-known/", self.),
                # web.get("/.well-known/", self.),
                web.post("/credential", self.issue_cred),
                web.get("/credential-offer", self.get_cred_offer),
                web.post("/token", self.get_token),
                web.get("/", self.redirect_handler, allow_head=True),
                web.post("/status/reset", self.status_reset_handler),
                web.get("/status/live", self.liveliness_handler, allow_head=False),
                web.get("/status/ready", self.readiness_handler, allow_head=False),
            ]
        )

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
        agent_label = self.context.settings.get("default_label")
        __version__ = 11  # TODO: get dynamically from config
        version_string = f"v{__version__}"

        setup_aiohttp_apispec(
            app=app, title=agent_label, version=version_string, swagger_path="/api/doc"
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

    @docs(tags=["oid4vci"], summary="Reset statistics")
    @response_schema(TokenRequestSchema(), 200, description="")
    async def oid_cred_issuer(self, request: web.BaseRequest):
        pass

    @docs(tags=["oid4vci"], summary="Reset statistics")
    @response_schema(IssueCredentialRequestSchema(), 200, description="")
    async def issue_cred(self, request: web.BaseRequest):
        pass

    @docs(tags=["server"], summary="Get a credential offer")
    @querystring_schema(GetCredentialOfferSchema())
    async def get_cred_offer(self, request: web.BaseRequest):
        """
        Endpoint to retrieve an OIDC4VCI compliant offer, that
        can f.e. be used in QR-Code presented to a compliant wallet.
        """
        credentials = request.query["credentials"]
        credential_issuer_url = request.query["credential_issuer"]
        profile = request["context"].profile

        # TODO: check that the credential_issuer_url is associated with an issuer DID
        # TODO: check that the credential requested is offered by the issuer

        code = "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(code_size)
        )

        grants = {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": False,
            }
        }

        record = CredentialOfferRecord(
            credential_issuer_url=credential_issuer_url,
            credentials=credentials,
            grants=grants,
        )

        async with profile.session() as session:
            await record.save(session, reason="Save credential offer record.")

        return web.json_response(record)


    @docs(tags=["oid4vci"], summary="Reset statistics")
    @response_schema(TokenRequestSchema(), 200, description="")
    async def get_token(self, request: web.BaseRequest):
        """Token endpoint to exchange pre_authorized codes for access tokens."""
        

    @docs(tags=["server"], summary="Reset statistics")
    @response_schema(AdminResetSchema(), 200, description="")
    async def status_reset_handler(self, request: web.BaseRequest):
        """Request handler for resetting the timing statistics.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        collector = self.context.inject_or(Collector)
        if collector:
            collector.reset()
        return web.json_response({})

    async def redirect_handler(self, request: web.BaseRequest):
        """Perform redirect to documentation."""
        raise web.HTTPFound("/api/doc")

    @docs(tags=["server"], summary="Liveliness check")
    @response_schema(AdminStatusLivelinessSchema(), 200, description="")
    async def liveliness_handler(self, request: web.BaseRequest):
        """Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, always indicating True

        """
        app_live = self.app._state["alive"]
        if app_live:
            return web.json_response({"alive": app_live})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not available")

    @docs(tags=["server"], summary="Readiness check")
    @response_schema(AdminStatusReadinessSchema(), 200, description="")
    async def readiness_handler(self, request: web.BaseRequest):
        """Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, indicating readiness for further calls

        """
        app_ready = self.app._state["ready"] and self.app._state["alive"]
        if app_ready:
            return web.json_response({"ready": app_ready})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not ready")

    def notify_fatal_error(self):
        """Set our readiness flags to force a restart (openshift)."""
        LOGGER.error("Received shutdown request notify_fatal_error()")
        self.app._state["ready"] = False
        self.app._state["alive"] = False
