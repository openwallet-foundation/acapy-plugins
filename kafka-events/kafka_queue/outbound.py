"""Basic in memory queue."""
import json
import base64
from typing import Union

from aiokafka.producer.producer import AIOKafkaProducer
from aries_cloudagent.config.settings import Settings
from aries_cloudagent.transport.outbound.queue.base import (
    BaseOutboundQueue,
    OutboundQueueError,
)

from . import get_config


class KafkaOutboundQueue(BaseOutboundQueue):
    """Kafka queue implementation class."""

    def __init__(self, settings: Settings):
        """Initialize base queue type."""
        super().__init__(settings)
        self.producer = AIOKafkaProducer(**get_config(settings))

    async def start(self):
        """Start the queue."""
        await self.producer.start()

    async def stop(self):
        """Stop the queue."""
        await self.producer.stop()

    async def push(self, key: str, message: bytes):
        """Present only to fulfill base class."""

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

        message = str.encode(
            json.dumps(
                {
                    "headers": {"Content-Type": content_type},
                    "endpoint": endpoint,
                    "payload": base64.urlsafe_b64encode(payload).decode(),
                }
            ),
            encoding="utf8"
        )
        try:
            return await self.producer.send_and_wait("acapy-outbound-message", message)
        except Exception:
            self.logger.exception("Error while pushing to kafka")
