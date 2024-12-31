import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.anoncreds.registry import AnonCredsRegistry

from .did_resolver import HederaDIDResolver
from .anoncreds_registry import HederaAnonCredsRegistry

LOGGER = logging.getLogger(__name__)

async def setup(context: InjectionContext): 
    """Setup the plugin.""" 
    registry = context.inject_or(DIDResolver)
    if not registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return

    hedera_did_resolver_resolver = HederaDIDResolver()
    await hedera_did_resolver_resolver.setup(context) 
    registry.register_resolver(hedera_did_resolver_resolver)

    registry = context.inject_or(AnonCredsRegistry)
    if not registry:
        LOGGER.warning("No AnonCredsRegistry instance found in context")
        return

    hedera_anoncreds_registry = HederaAnonCredsRegistry()
    await hedera_anoncreds_registry.setup(context)
    registry.register(hedera_anoncreds_registry)
