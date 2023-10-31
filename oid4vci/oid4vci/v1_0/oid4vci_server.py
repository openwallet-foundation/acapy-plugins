"""Admin server classes."""

import logging
import jwt as pyjwt

import aiohttp_cors
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
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
from aries_cloudagent.wallet.jwt import jwt_verify
from marshmallow import fields
from .models.cred_sup_record import OID4VCICredentialSupported

LOGGER = logging.getLogger(__name__)


class IssueCredentialRequestSchema(OpenAPISchema):
    format = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )
    types = fields.List(
        fields.Str(),
        metadata={"description": "List of connection records"},
    )
    credentialsSubject = fields.Dict(metadata={"description": ""})
    proof = fields.Dict(metadata={"description": ""})


class TokenRequestSchema(OpenAPISchema):
    """Request schema for the /token endpoint."""

    client_id = fields.Str(
        required=True,
        metadata={"description": "The client ID for the token request.", "example": ""},
    )


class GetTokenSchema(OpenAPISchema):
    """Schema for ..."""

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        required=True, metadata={"description": "", "example": ""}
    )


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
                # public oid4vci
                "/.well-known/openid-credential-issuer",
                "/token",
                "/credential-offer",
                # public swagger
                "/api/doc",
                "/api/docs/swagger.json",
                # non protected health checks
                "/status/live",
                "/status/ready",
            ] or path.startswith("/static/swagger/")

        @web.middleware
        async def check_token(request: web.Request, handler):
            # get token
            authorization_header = request.headers.get("Authorization")
            if is_unprotected_path(request.path):
                return await handler(request)

            if not authorization_header:
                raise web.HTTPUnauthorized()  # no authentication

            scheme, cred = authorization_header.split(" ")
            if scheme.lower() != "bearer" or ():
                raise web.HTTPUnauthorized()  # Invalid authentication credentials

            jwt_header = pyjwt.get_unverified_header(cred)
            if "did:key:" not in jwt_header["kid"]:
                raise web.HTTPUnauthorized()  # Invalid authentication credentials

            result = await jwt_verify(self.profile, cred)
            if result.valid:
                return await handler(request)
            else:
                raise web.HTTPUnauthorized()  # Invalid credentials

        middlewares.append(check_token)

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
                web.get(
                    "/.well-known/openid-credential-issuer",
                    self.oid_cred_issuer,
                    allow_head=False,
                ),
                # web.get("/.well-known/", self., allow_head=False),
                # web.get("/.well-known/", self., allow_head=False),
                web.post("/credential", self.issue_cred),
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

    @docs(tags=["oid4vci"], summary="Get credential issuer metadata")
    @querystring_schema(TokenRequestSchema())
    async def oid_cred_issuer(self, request: web.BaseRequest):
        """Credential issuer metadata endpoint."""
        profile = request["context"].profile
        public_url = profile.context.settings.get("public_url")  # TODO: check

        # Wallet query to retrieve credential definitions
        tag_filter = {"type": {"$in": ["sd_jwt", "jwt_vc_json"]}}
        async with profile.session() as session:
            credentials_supported = await OID4VCICredentialSupported.query(
                session, tag_filter
            )

        metadata = {
            "credential_issuer": f"{public_url}/issuer",
            "credential_endpoint": f"{public_url}/credential",
            "credentials_supported": [
                cred.serialize() for cred in credentials_supported
            ],
            "authorization_server": f"{public_url}/auth-server",
            "batch_credential_endpoint": f"{public_url}/batch_credential",
        }

        return web.json_response(metadata)

    @docs(tags=["oid4vci"], summary="Issue a credential")
    @request_schema(IssueCredentialRequestSchema())
    async def issue_cred(self, request: web.BaseRequest):
        pass

    @docs(tags=["oid4vci"], summary="Get credential issuance token")
    @querystring_schema(TokenRequestSchema())
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
