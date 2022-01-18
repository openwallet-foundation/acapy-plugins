"""Basic in memory queue."""
import base64
import json

from aries_cloudagent.core.profile import Profile
from kafka_queue.config import OutboundConfig
import logging
from typing import List, Optional, Union

from aiokafka.producer.producer import AIOKafkaProducer
from aries_cloudagent.transport.outbound.queue.base import (
    BaseOutboundQueue,
    OutboundQueueError,
)

from . import get_config


LOGGER = logging.getLogger(__name__)


def b64_to_bytes(val: Union[str, bytes], urlsafe=False) -> bytes:
    """Convert a base 64 string to bytes."""
    if isinstance(val, str):
        val = val.encode("ascii")
    if urlsafe:
        missing_padding = len(val) % 4
        if missing_padding:
            val += b"=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(val)
    return base64.b64decode(val)


def _recipients_from_packed_message(packed_message: bytes) -> List[str]:
    """
    Inspect the header of the packed message and extract the recipient key.
    """
    try:
        wrapper = json.loads(packed_message)
    except Exception as err:
        raise ValueError("Invalid packed message") from err

    recips_json = b64_to_bytes(wrapper["protected"], urlsafe=True).decode("ascii")
    try:
        recips_outer = json.loads(recips_json)
    except Exception as err:
        raise ValueError("Invalid packed message recipients") from err

    return [recip["header"]["kid"] for recip in recips_outer["recipients"]]


class KafkaOutboundQueue(BaseOutboundQueue):
    """Kafka queue implementation class."""

    DEFAULT_OUTBOUND_TOPIC = "acapy-outbound-message"

    def __init__(self, profile: Profile):
        """Initialize base queue type."""
        super().__init__(profile)
        self.config = get_config(profile.settings).outbound or OutboundConfig.default()
        LOGGER.info(
            f"Setting up kafka outbound queue with configuration: {self.config}"
        )
        self.producer: Optional[AIOKafkaProducer] = None

    async def start(self):
        """Start the queue."""
        LOGGER.info("Starting kafka outbound queue producer")
        self.producer = AIOKafkaProducer(**self.config.producer.dict())
        await self.producer.start()

    async def stop(self):
        """Stop the queue."""
        LOGGER.info("Stopping kafka outbound queue producer")
        if self.producer:
            await self.producer.stop()

    async def enqueue_message(
        self,
        payload: Union[str, bytes],
        endpoint: str,
    ):
        """Prepare and send message to external queue."""
        if not self.producer:
            raise OutboundQueueError("No producer started")
        if not endpoint:
            raise OutboundQueueError("No endpoint provided")

        message = str.encode(
            json.dumps(
                {
                    "service": {"url": endpoint},
                    "payload": base64.urlsafe_b64encode(payload).decode(),
                }
            ),
        )
        topic = self.config.topic
        partition_key = ",".join(_recipients_from_packed_message(payload)).encode()

        try:
            LOGGER.info(
                "  - Producing message for kafka: (%s)[%s]: %s",
                topic,
                partition_key,
                message,
            )
            return await self.producer.send_and_wait(topic, message, key=partition_key)
        except Exception:
            LOGGER.exception("Error while pushing to kafka")
