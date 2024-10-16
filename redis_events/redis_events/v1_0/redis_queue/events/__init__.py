"""ACA-Py Event to Redis."""

import base64
import json
import logging
import re
from string import Template
from typing import Any, Optional, cast

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import Event, EventBus, EventWithMetadata
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import SHUTDOWN_EVENT_PATTERN, STARTUP_EVENT_PATTERN
from acapy_agent.transport.error import TransportError
from redis.asyncio import RedisCluster
from redis.exceptions import RedisClusterException, RedisError

from ..config import EventConfig, OutboundConfig, get_config

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("> plugin setup...")
    config = get_config(context.settings).event or EventConfig.default()

    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    for event in config.event_topic_maps.keys():
        LOGGER.info(f"subscribing to event: {event}")
        bus.subscribe(re.compile(event), handle_event)

    bus.subscribe(STARTUP_EVENT_PATTERN, on_startup)
    bus.subscribe(SHUTDOWN_EVENT_PATTERN, on_shutdown)
    LOGGER.info("< plugin setup.")


RECORD_RE = re.compile(r"acapy::record::([^:]*)(?:::(.*))?")
WEBHOOK_RE = re.compile(r"acapy::webhook::{.*}")


async def redis_setup(profile: Profile, event: Event) -> RedisCluster:
    """Connect, setup and return the Redis instance."""
    connection_url = (get_config(profile.settings).connection).connection_url
    try:
        redis = RedisCluster.from_url(url=connection_url)
        await redis.ping(target_nodes=RedisCluster.PRIMARIES)
        profile.context.injector.bind_instance(RedisCluster, redis)
    except (RedisError, RedisClusterException) as err:
        raise TransportError(f"No Redis instance setup, {err}")
    return redis


async def on_startup(profile: Profile, event: Event):
    """Setup Redis on startup."""
    await redis_setup(profile, event)


async def on_shutdown(profile: Profile, event: Event):
    """Called on shutdown."""
    pass


def _derive_category(topic: str):
    match = RECORD_RE.match(topic)
    if match:
        return match.group(1)
    if WEBHOOK_RE.match(topic):
        return "webhook"


def process_event_payload(event_payload: Any):
    """Process event payload."""
    processed_event_payload = None
    if isinstance(event_payload, dict):
        processed_event_payload = event_payload
    else:
        processed_event_payload = json.loads(event_payload)
    return processed_event_payload


async def handle_event(profile: Profile, event: EventWithMetadata):
    """Push events from aca-py events."""
    redis = profile.inject_or(RedisCluster)
    if not redis:
        redis = await redis_setup(profile, event)

    LOGGER.info("Handling event: %s", event)
    wallet_id = cast(Optional[str], profile.settings.get("wallet.id"))
    try:
        event_payload = process_event_payload(event.payload)
    except TypeError:
        try:
            event_payload = event.payload.serialize()
        except AttributeError:
            try:
                event_payload = process_event_payload(event.payload.payload)
            except TypeError:
                event_payload = process_event_payload(event.payload.enc_payload)
    payload = {
        "wallet_id": wallet_id or "base",
        "state": event_payload.get("state"),
        "topic": event.topic,
        "category": _derive_category(event.topic),
        "payload": event_payload,
    }
    webhook_urls = profile.settings.get("admin.webhook_urls")
    try:
        config_events = get_config(profile.settings).event or EventConfig.default()
        template = config_events.event_topic_maps[event.metadata.pattern.pattern]
        redis_topic = Template(template).substitute(**payload)
        LOGGER.info(f"Sending message {payload} with topic {redis_topic}")
        outbound = str.encode(
            json.dumps(
                {
                    "payload": payload,
                    "metadata": {"x-wallet-id": wallet_id} if wallet_id else {},
                }
            ),
        )
        await redis.rpush(
            redis_topic,
            outbound,
        )
        # Deliver/dispatch events to webhook_urls directly
        if config_events.deliver_webhook and webhook_urls:
            config_outbound = (
                get_config(profile.settings).outbound or OutboundConfig.default()
            )
            for endpoint in webhook_urls:
                api_key = None
                if len(endpoint.split("#")) > 1:
                    endpoint_hash_split = endpoint.split("#")
                    endpoint = endpoint_hash_split[0]
                    api_key = endpoint_hash_split[1]
                webhook_topic = config_events.event_webhook_topic_maps.get(event.topic)
                if endpoint and webhook_topic:
                    endpoint = f"{endpoint}/topic/{webhook_topic}/"
                    headers = {"x-wallet-id": wallet_id} if wallet_id else {}
                    if api_key is not None:
                        headers["x-api-key"] = api_key
                    outbound_msg = {
                        "service": {"url": endpoint},
                        "payload": base64.urlsafe_b64encode(
                            str.encode(json.dumps(payload))
                        ).decode(),
                        "headers": headers,
                    }
                    await redis.rpush(
                        config_outbound.acapy_outbound_topic,
                        str.encode(json.dumps(outbound_msg)),
                    )
    except (RedisError, RedisClusterException, ValueError) as err:
        LOGGER.exception(f"Failed to process and send webhook, {err}")
