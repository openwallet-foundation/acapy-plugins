"""ACA-Py Event to Kafka Bridge."""

import json
import logging
import re
from string import Template
from typing import Any, Mapping

from aiokafka import AIOKafkaProducer
from aries_cloudagent.config.base import BaseSettings
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import EventBus, EventWithMetadata
from aries_cloudagent.core.profile import Profile

DEFAULT_CONFIG = {
    "producer": {
        "bootstrap_servers": "kafka",
    },
    "outbound_topic_templates": {
        "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
        "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
        "^acapy::record::([^:])?": "acapy-record-$wallet_id",
        "acapy::basicmessage::received": "acapy-basicmessage-received",
    },
    "proxy": False,
}

LOGGER = logging.getLogger(__name__)


def get_config(settings: BaseSettings) -> Mapping[str, Any]:
    """Retrieve producer configuration from settings."""
    try:
        producer_conf = settings["plugin_config"]["kafka_queue"] or DEFAULT_CONFIG
    except KeyError:
        producer_conf = DEFAULT_CONFIG

    return producer_conf


async def setup(context: InjectionContext):
    """Setup the plugin."""
    config = get_config(context.settings)
    LOGGER.info(f"Setting up kafka plugin with configuration: {config}")
    producer = AIOKafkaProducer(**config.get("producer", {}))
    LOGGER.info("  - Starting kafka producer")
    await producer.start()

    # Add the Kafka producer in the context
    context.injector.bind_instance(AIOKafkaProducer, producer)
    LOGGER.info("   - Subscribing Kafka producer to eventbus events")

    # Handle event for Kafka
    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    for event in config.get("outbound_topic_templates", {}):
        LOGGER.info(f"      - subscribing to event: {event}")
        bus.subscribe(re.compile(event), handle_event)


async def handle_event(profile: Profile, event: EventWithMetadata):
    """
    produce kafka events from eventbus events
    """

    producer = profile.inject(AIOKafkaProducer)
    if not producer:
        raise ValueError("AIOKafkaProducer missing in context")

    LOGGER.info("Handling Kafka producer event: %s", event)
    event.payload["wallet_id"] = profile.settings.get("wallet.id", "base")
    config = get_config(profile.settings)
    try:
        template = config.get("outbound_topic_templates", {})[
            event.metadata.pattern.pattern
        ]
        kafka_topic = Template(template).substitute(**event.payload)
        LOGGER.info(f"Sending message {event.payload} with Kafka topic {kafka_topic}")
        # Produce message
        await producer.send_and_wait(
            kafka_topic,
            str.encode(json.dumps(event.payload)),
            key=profile.settings.get("wallet.id"),
        )
    except Exception:
        LOGGER.exception("Kafka producer failed to send message")
