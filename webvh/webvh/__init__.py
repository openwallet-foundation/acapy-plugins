import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.core.protocol_registry import ProtocolRegistry

from .protocols.attested_resource.message_types import (
    MESSAGE_TYPES as ATTESTED_RESOURCE_MESSAGE_TYPES,
)
from .protocols.log_entry.message_types import (
    MESSAGE_TYPES as LOG_ENTRY_MESSAGE_TYPES,
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
    protocol_registry.register_message_types(ATTESTED_RESOURCE_MESSAGE_TYPES)
    protocol_registry.register_message_types(LOG_ENTRY_MESSAGE_TYPES)
