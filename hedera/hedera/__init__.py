import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.wallet.did_method import DIDMethods

from .anoncreds import HederaAnonCredsRegistry
from .did import HEDERA, HederaDIDResolver

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    did_resolver_registry = context.inject_or(DIDResolver)
    if not did_resolver_registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return

    hedera_did_resolver = HederaDIDResolver()
    await hedera_did_resolver.setup(context)
    did_resolver_registry.register_resolver(hedera_did_resolver)

    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    if not anoncreds_registry:
        LOGGER.warning("No AnonCredsRegistry instance found in context")
        return

    hedera_anoncreds_registry = HederaAnonCredsRegistry()
    await hedera_anoncreds_registry.setup(context)
    anoncreds_registry.register(hedera_anoncreds_registry)

    did_methods = context.inject(DIDMethods)
    did_methods.register(HEDERA)
