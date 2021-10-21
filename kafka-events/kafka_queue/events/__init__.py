"""ACA-Py Event to Kafka Bridge."""

import json
import logging
import re
from string import Template

from aiokafka import AIOKafkaProducer
from aries_cloudagent.core.event_bus import EventBus, EventWithMetadata
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.config.injection_context import InjectionContext

from .. import get_config


LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    config = get_config(context.settings).events
    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    for event in config.topic_maps.keys():
        LOGGER.info(f"subscribing to event: {event}")
        bus.subscribe(re.compile(event), handle_event)


async def handle_event(profile: Profile, event: EventWithMetadata):
    """Produce kafka events from aca-py events."""

    LOGGER.info("Handling Kafka producer event: %s", event)
    event.payload["wallet_id"] = profile.settings.get("wallet.id", "base")
    config = get_config(profile.settings).events
    try:
        template = config.topic_maps[event.metadata.pattern.pattern]
        kafka_topic = Template(template).substitute(**event.payload)
        LOGGER.info(f"Sending message {event.payload} with Kafka topic {kafka_topic}")
        # Produce message
        async with AIOKafkaProducer(**config.producer.dict()) as producer:
            await producer.send_and_wait(
                kafka_topic,
                str.encode(json.dumps(event.payload)),
                key=profile.settings.get("wallet.id"),
            )
    except Exception:
        LOGGER.exception("Kafka producer failed to send message")
