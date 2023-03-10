"""Basic in memory queue."""
import base64
import json
import logging
import ssl
from typing import List, Optional, Union

from aiokafka.producer.producer import AIOKafkaProducer

from aries_cloudagent.core.profile import Profile
from aries_cloudagent.transport.outbound.base import (
    BaseOutboundTransport,
    OutboundTransportError,
)
from aries_cloudagent.transport.outbound.manager import QueuedOutboundMessage

from .config import get_config, OutboundConfig

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


class KafkaOutboundQueue(BaseOutboundTransport):
    """Kafka queue implementation class."""

    DEFAULT_OUTBOUND_TOPIC = "acapy-outbound-message"
    schemes = ("kafka",)
    is_external = True

    def __init__(self, root_profile: Profile):
        """Initialize base queue type."""
        super().__init__(root_profile=root_profile)
        LOGGER.info(get_config(root_profile.settings))

        self.config = (
            get_config(root_profile.settings).outbound or OutboundConfig.default()
        )
        LOGGER.info(
            f"Setting up kafka outbound queue with configuration: {self.config}"
        )

        self.producer: Optional[AIOKafkaProducer] = None

    async def start(self):
        """Start the queue."""
        LOGGER.info("Starting kafka outbound queue producer")

        self.producer = AIOKafkaProducer(
            **self.config.producer.dict(),
            ssl_context=ssl.create_default_context()
            if self.config.producer.ssl_required
            else None,
        )
        await self.producer.start()

    async def stop(self):
        """Stop the queue."""
        LOGGER.info("Stopping kafka outbound queue producer")
        if self.producer:
            await self.producer.stop()

    async def handle_message(
        self,
        profile: Profile,
        outbound_message: QueuedOutboundMessage,
        endpoint: str,
        metadata: dict = None,
    ):
        """Prepare and send message to external queue."""
        if not self.producer:
            raise OutboundTransportError("No producer started")
        if not endpoint:
            raise OutboundTransportError("No endpoint provided")

        message_dict = {
            "service": {"url": endpoint},
            "metadata": {
                "wallet_id": profile.settings.get("wallet.id"),
                "connection_id": outbound_message.message.connection_id,
                "message": outbound_message.message.payload,
            },
            "payload": base64.urlsafe_b64encode(outbound_message.payload).decode(),
        }
        json_message = str.encode(
            json.dumps(message_dict),
        )

        topic = self.config.topic
        partition_key = ",".join(
            _recipients_from_packed_message(outbound_message.payload)
        ).encode()

        try:
            LOGGER.info(
                "  - Producing message for kafka: (%s)[%s]: %s",
                topic,
                partition_key,
                json_message,
            )
            return await self.producer.send_and_wait(
                topic, json_message, key=partition_key
            )
        except Exception:
            LOGGER.exception("Error while pushing to kafka")
