"""ACA-Py Event to Kafka Bridge."""

import json
import logging
import re
from string import Template

from aiokafka import AIOKafkaProducer
from aries_cloudagent.core.event_bus import EventBus, EventWithMetadata
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.config.injection_context import InjectionContext

from ..config import get_config, EventsConfig


LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    config = get_config(context.settings).events
    if not config:
        config = EventsConfig.default()

    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    for event in config.topic_maps.keys():
        LOGGER.info(f"subscribing to event: {event}")
        bus.subscribe(re.compile(event), handle_event)


RECORD_RE = re.compile(r"acapy::record::([^:]*)(?:::(.*))?")
WEBHOOK_RE = re.compile(r"acapy::webhook::{.*}")


def _derive_category(topic: str):
    match = RECORD_RE.match(topic)
    if match:
        return match.group(1)
    if WEBHOOK_RE.match(topic):
        return "webhook"


async def handle_event(profile: Profile, event: EventWithMetadata):
    """Produce kafka events from aca-py events."""

    LOGGER.info("Handling Kafka producer event: %s", event)
    payload = {
        "wallet_id": profile.settings.get("wallet.id", "base"),
        "state": event.payload.get("state"),
        "topic": event.topic,
        "category": _derive_category(event.topic),
        "payload": event.payload,
    }
    config = get_config(profile.settings).events or EventsConfig.default()
    try:
        template = config.topic_maps[event.metadata.pattern.pattern]
        kafka_topic = Template(template).substitute(**payload)
        LOGGER.info(f"Sending message {payload} with Kafka topic {kafka_topic}")
        # Produce message
        async with AIOKafkaProducer(**config.producer.dict()) as producer:
            await producer.send_and_wait(
                kafka_topic,
                str.encode(json.dumps(payload)),
                key=profile.settings.get("wallet.id"),
            )
    except Exception:
        LOGGER.exception("Kafka producer failed to send message")
