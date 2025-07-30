import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.core.protocol_registry import ProtocolRegistry

from .protocols.endorse_attested_resource.messages import (
    MESSAGE_TYPES as endorse_attested_resource_message_types,
)
from .protocols.witness_log_entry.messages import (
    MESSAGE_TYPES as witness_log_entry_message_types,
)

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup."""
    LOGGER.info("webvh plugin setup...")

    # AnonCreds Registry
    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    if not anoncreds_registry:
        LOGGER.warning("No AnonCreds Registry instance found in context")
        return

    webvh_registry = ClassProvider("webvh.anoncreds.registry.DIDWebVHRegistry").provide(
        context.settings, context.injector
    )
    await webvh_registry.setup(context)
    LOGGER.info("Registering DIDWebVHRegistry")
    anoncreds_registry.register(webvh_registry)

    # Did-comm message types
    protocol_registry = context.inject(ProtocolRegistry)
    LOGGER.info("Registering did:webvh message types")
    protocol_registry.register_message_types(endorse_attested_resource_message_types)
    protocol_registry.register_message_types(witness_log_entry_message_types)
