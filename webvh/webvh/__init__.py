import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.core.protocol_registry import ProtocolRegistry
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.wallet.did_method import DIDMethods

from .did_method import WEBVH
from .resolver.resolver import DIDWebVHResolver
from .did.message_types import MESSAGE_TYPES

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup."""
    LOGGER.info("webvh plugin setup...")

    # Anoncreds Registry
    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    if not anoncreds_registry:
        LOGGER.warning("No Anoncreds Registry instance found in context")
        return

    webvh_registry = ClassProvider("webvh.anoncreds.registry.DIDWebVHRegistry").provide(
        context.settings, context.injector
    )
    await webvh_registry.setup(context)
    LOGGER.info("Registering DIDWebVHRegistry")
    anoncreds_registry.register(webvh_registry)
    
    # Register WebVH Resolver
    resolver_registry = context.inject_or(DIDResolver)
    if not resolver_registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return
    resolver_registry.register_resolver(DIDWebVHResolver())

    # Register WebVH DID Method
    did_methods = context.inject_or(DIDMethods)
    did_methods.register(WEBVH)

    # Did-comm message types
    protocol_registry = context.inject(ProtocolRegistry)
    LOGGER.info("Registering did:webvh message types")
    protocol_registry.register_message_types(MESSAGE_TYPES)
