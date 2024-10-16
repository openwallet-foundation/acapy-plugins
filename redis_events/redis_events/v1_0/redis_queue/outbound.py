"""Basic in memory queue."""

import base64
import json
import logging

from acapy_agent.core.profile import Profile
from acapy_agent.transport.outbound.base import (
    BaseOutboundTransport,
    OutboundTransportError,
    QueuedOutboundMessage,
)
from acapy_agent.transport.wire_format import (
    DIDCOMM_V0_MIME_TYPE,
    DIDCOMM_V1_MIME_TYPE,
)
from redis.asyncio import RedisCluster
from redis.exceptions import RedisClusterException, RedisError

from .config import ConnectionConfig, OutboundConfig, get_config
from .utils import process_payload_recip_key

LOGGER = logging.getLogger(__name__)


class RedisOutboundQueue(BaseOutboundTransport):
    """Redis queue implementation class."""

    DEFAULT_OUTBOUND_TOPIC = "acapy_outbound"
    schemes = ("redis",)
    is_external = True

    def __init__(
        self,
        root_profile,
        **kwargs,
    ):
        """Initialize base queue type."""
        super().__init__(**kwargs)
        self.outbound_config = (
            get_config(root_profile.context.settings).outbound or OutboundConfig.default()
        )
        LOGGER.info(
            "Setting up redis outbound queue with configuration: %s",
            self.outbound_config,
        )
        self.redis = root_profile.inject_or(RedisCluster)
        self.is_mediator = self.outbound_config.mediator_mode
        self.outbound_topic = self.outbound_config.acapy_outbound_topic
        if not self.redis:
            self.connection_url = (
                get_config(root_profile.context.settings).connection
                or ConnectionConfig.default()
            ).connection_url
            self.redis = RedisCluster.from_url(url=self.connection_url)

    async def start(self):
        """Start the queue."""
        await self.redis.ping(target_nodes=RedisCluster.PRIMARIES)

    async def stop(self):
        """Stop the queue."""

    async def handle_message(
        self,
        profile: Profile,
        outbound_message: QueuedOutboundMessage,
        endpoint: str,
        metadata: dict = None,
        api_key: str = None,
    ):
        """Prepare and send message to external queue."""
        payload = outbound_message.payload
        if not endpoint:
            raise OutboundTransportError("No endpoint provided")
        headers = metadata or {}
        if api_key is not None:
            headers["x-api-key"] = api_key
        if isinstance(payload, bytes):
            if profile.settings.get("emit_new_didcomm_mime_type"):
                headers["Content-Type"] = DIDCOMM_V1_MIME_TYPE
            else:
                headers["Content-Type"] = DIDCOMM_V0_MIME_TYPE
        else:
            headers["Content-Type"] = "application/json"
            payload = payload.encode("utf-8")
        topic = self.outbound_topic
        message = str.encode(
            json.dumps(
                {
                    "service": {"url": endpoint},
                    "payload": base64.urlsafe_b64encode(payload).decode(),
                    "headers": headers,
                }
            ),
        )
        if self.is_mediator:
            topic, message = await process_payload_recip_key(self.redis, payload, topic)
        try:
            LOGGER.info(
                "  - Adding outbound message to Redis: (%s): %s",
                topic,
                message,
            )
            await self.redis.rpush(
                topic,
                message,
            )
        except (RedisError, RedisClusterException) as err:
            LOGGER.exception("Error while pushing to Redis: %s", err)
