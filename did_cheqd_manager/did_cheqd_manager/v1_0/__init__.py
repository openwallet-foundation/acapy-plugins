import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.wallet.did_method import DIDMethods

from .did_method import CHEQD
from .resolver import CheqdDIDResolver

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""

    LOGGER.info("< did_cheqd_manager plugin setup...")
    # Register Cheqd DID Resolver
    resolver_registry = context.inject_or(DIDResolver)
    if not resolver_registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return
    resolver_registry.register_resolver(CheqdDIDResolver())

    # Register Anoncreds provider
    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    if not anoncreds_registry:
        LOGGER.warning("No Anoncreds Registry instance found in context")
        return
    cheqd_registry = ClassProvider(
        "did_cheqd_manager.v1_0.anoncreds.registry.DIDCheqdRegistry",
        # supported_identifiers=[],
        # method_name="did:cheqd",
    ).provide(context.settings, context.injector)
    await cheqd_registry.setup(context)
    anoncreds_registry.register(cheqd_registry)

    # Register Cheqd DID Method
    did_methods = context.inject_or(DIDMethods)
    did_methods.register(CHEQD)

    LOGGER.info("< did_cheqd_manager plugin setup.")
