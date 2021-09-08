"""ACA-Py Event to Kafka Bridge."""

import json
import logging
import re
from typing import Any, Mapping

from aiokafka import AIOKafkaProducer
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.settings import Settings
from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.profile import Profile

DEFAULT_CONFIG = {
    "bootstrap_servers": "kafka",
    "outbound_topics": [
        "^acapy::webhook::(.*)$",
        "^acapy::record::([^:]*)(?:::.*)?$",
        "acapy::basicmessage::.*",
    ],
}

LOGGER = logging.getLogger(__name__)


def get_config(settings: Settings) -> Mapping[str, Any]:
    """Retrieve producer configuration from settings."""
    try:
        producer_conf = (
            settings["plugin_config"]["kafka_queue"]["producer-config"]
            or DEFAULT_CONFIG
        )
    except KeyError:
        producer_conf = DEFAULT_CONFIG

    return producer_conf


async def setup(context: InjectionContext):
    """Setup the plugin."""
    config = get_config(context.settings)
    producer = AIOKafkaProducer(**config)
    await producer.start()

    # Add the Kafka producer in the context
    context.injector.bind_instance(AIOKafkaProducer, producer)

    # Handle event for Kafka
    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    for event in config.get("outbound_topics"):
        bus.subscribe(re.compile(event), handle_event)


async def handle_event(profile: Profile, event: Event):
    """
    produce kafka events from eventbus events

    ACA-Py eventbus events are namespaced with `acapy`; for example:

        acapy::record::present_proof::presentation_received

    There are two primary namespaces of ACA-Py events.
    - `record`: record update events. These
      follow the pattern:
        - stateful, acapy::record::{RECORD_TOPIC}::{STATE}
        - stateless, acapy::record::{RECORD_TOPIC}
      note, majority of records are stateful.
    - `webhook`: events that notify controllers about changes.
        - ...TODO: add webhook event example
    """

    producer = profile.inject(AIOKafkaProducer)
    if not producer:
        raise ValueError("AIOKafkaProducer missing in context")

    LOGGER.info("Handling Kafka producer event: %s", event)
    topic = event.topic.replace("::", "-")
    event.payload["wallet_id"] = profile.settings.get("wallet.id")
    try:
        LOGGER.info(f"Sending message {event.payload} with Kafka topic {topic}")
        # Produce message
        await producer.send_and_wait(topic, str.encode(json.dumps(event.payload)))
    except Exception:
        LOGGER.exception("Kafka producer failed to send message")
