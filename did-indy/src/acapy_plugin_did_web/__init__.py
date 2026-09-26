"""DID Web."""

from os import getenv
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.wallet.did_method import DIDMethods

from .did import WEB
from .client import DidWebServerClient


async def setup(context: InjectionContext):
    methods = context.inject(DIDMethods)
    methods.register(WEB)

    config = context.settings.for_plugin("acapy_did_web")
    server_base_url = config.get("server_base_url") or getenv("DID_WEB_SERVER_URL")
    if not server_base_url:
        raise ValueError("Failed to load did:web server base url")

    context.injector.bind_instance(
        DidWebServerClient, DidWebServerClient(server_base_url)
    )
