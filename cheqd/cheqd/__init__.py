import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.wallet.did_method import DIDMethods

from .did_method import CHEQD
from .resolver.resolver import CheqdDIDResolver

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""

    LOGGER.info("< cheqd plugin setup...")
    config = context.settings.get("plugin_config")
    resolver_url = None
    registrar_url = None
    if config:
        resolver_url = config.get("resolver_url")
        registrar_url = config.get("registrar_url")

    # Register Cheqd DID Resolver
    resolver_registry = context.inject_or(DIDResolver)
    if not resolver_registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return
    resolver_registry.register_resolver(CheqdDIDResolver(resolver_url))

    # Register Anoncreds provider
    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    if not anoncreds_registry:
        LOGGER.warning("No Anoncreds Registry instance found in context")
        return
    cheqd_registry = ClassProvider(
        "cheqd.anoncreds.registry.DIDCheqdRegistry",
        # supported_identifiers=[],
        # method_name="did:cheqd",
    ).provide(context.settings, context.injector)
    await cheqd_registry.setup(context, registrar_url, resolver_url)
    anoncreds_registry.register(cheqd_registry)

    # Register Cheqd DID Method
    did_methods = context.inject_or(DIDMethods)
    did_methods.register(CHEQD)

    LOGGER.info("< cheqd plugin setup.")
