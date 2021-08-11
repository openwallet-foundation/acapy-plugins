"""Basic in memory queue."""
import asyncio
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

    async def __aenter__(self):
        """Async context manager enter."""
        await self.start()

    async def __aexit__(self, err_type, err_value, err_t):
        """Async context manager exit."""
        if err_type and err_type != asyncio.CancelledError:
            self.logger.exception("Exception in outbound queue")
        await self.stop()

    async def start(self):
        """Start the queue."""

    async def stop(self):
        """Stop the queue."""

    async def push(self, key: bytes, message: bytes):
        """Push a ``message`` to queue on ``key``."""
        try:
            return await self.producer.send_and_wait(key, message)
        except Exception:
            self.logger.exception("Error while pushing to kafka")

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
            )
        )
        return await self.push("acapy-outbound-message".encode(), message)
