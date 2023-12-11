import logging
import re

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import EventBus, Event
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.core.protocol_registry import ProtocolRegistry
from aries_cloudagent.multitenant.admin.routes import (
    ACAPY_LIFECYCLE_CONFIG_FLAG_MAP,
    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP,
)
from .models import BasicMessageRecord
from .config import get_config

LOGGER = logging.getLogger(__name__)

BASIC_MESSAGE_EVENT_PATTERN = re.compile("^acapy::basicmessage::received$")


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("> plugin setup...")
    protocol_registry = context.inject(ProtocolRegistry)
    assert protocol_registry

    event_bus = context.inject(EventBus)
    if not event_bus:
        raise ValueError("EventBus missing in context")

    # add subwallet config
    ACAPY_LIFECYCLE_CONFIG_FLAG_ARGS_MAP[
        "basicmessage-storage"
    ] = "basicmessage_storage.enabled"

    event_bus.subscribe(BASIC_MESSAGE_EVENT_PATTERN, basic_message_event_handler)
    LOGGER.info("< plugin setup.")


async def basic_message_event_handler(profile: Profile, event: Event):
    """Event handler for Basic Messages."""
    LOGGER.info(event.payload)
    # grab the received event and persist it.
    msg: BasicMessageRecord = BasicMessageRecord.deserialize(event.payload)
    msg.state = BasicMessageRecord.STATE_RECV
    LOGGER.info(msg)
    LOGGER.info(profile.settings)
    LOGGER.info(get_config(profile.settings))
    if get_config(profile.settings).wallet_enabled:
        async with profile.session() as session:
            await msg.save(session, reason="New received message")
            LOGGER.info(msg)
    else:
        LOGGER.info("basicmessage not saved, basicmessage_storage.wallet_enabled=False")
