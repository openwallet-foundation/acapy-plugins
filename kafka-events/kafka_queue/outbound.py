"""Basic in memory queue."""
import base64
import json
import logging
from typing import Union

from aiokafka.producer.producer import AIOKafkaProducer
from aries_cloudagent.config.settings import Settings
from aries_cloudagent.transport.outbound.queue.base import (
    BaseOutboundQueue,
    OutboundQueueError,
)

from . import get_config

LOGGER = logging.getLogger(__name__)


class KafkaOutboundQueue(BaseOutboundQueue):
    """Kafka queue implementation class."""

    def __init__(self, settings: Settings):
        """Initialize base queue type."""
        super().__init__(settings)
        config = get_config(self.root_profile.context.settings)
        LOGGER.info(f"Setting up kafka outbound queue with configuration: {config}")
        self.producer = AIOKafkaProducer(**config.get("producer"))

    async def start(self):
        """Start the queue."""
        LOGGER.info("  - Starting kafka outbound queue producer")
        await self.producer.start()

    async def stop(self):
        """Stop the queue."""
        LOGGER.info("  - Stopping kafka outbound queue producer")
        await self.producer.stop()

    async def push(self, key: str, message: bytes):
        """Present only to fulfill base class."""
        raise NotImplementedError

    async def enqueue_message(
        self,
        payload: Union[str, bytes],
        endpoint: str,
    ):
        """Prepare and send message to external queue."""
        if not endpoint:
            raise OutboundQueueError("No endpoint provided")
        if isinstance(payload, bytes):
            content_type = "application/ssi-agent-wire"
        else:
            content_type = "application/json"
            payload = payload.encode(encoding="utf-8")
        config = get_config(self.root_profile.context.settings)
        if config.get("proxy", False):
            LOGGER.info("  - Preparing proxy message for queue")
            message = str.encode(
                json.dumps(
                    {
                        "headers": {"Content-Type": content_type},
                        "endpoint": endpoint,
                        "payload": base64.urlsafe_b64encode(payload).decode(),
                    }
                )
            )
        else:
            LOGGER.info("  - Preparing message for queue")
            message = str.encode(json.dumps(base64.urlsafe_b64encode(payload).decode()))
        try:
            LOGGER.info("  - Producing message for kafka")
            return await self.producer.send_and_wait("acapy-outbound-message", message)
        except Exception:
            LOGGER.exception("Error while pushing to kafka")
