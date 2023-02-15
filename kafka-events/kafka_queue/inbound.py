import base64
import json
import logging
import ssl
from json import JSONDecodeError
from typing import cast

from aiokafka import AIOKafkaConsumer
from aiokafka.structs import ConsumerRecord

from aries_cloudagent.messaging.error import MessageParseError
from aries_cloudagent.transport.error import WireFormatParseError
from aries_cloudagent.transport.inbound.base import BaseInboundTransport
from .config import get_config, InboundConfig

LOGGER = logging.getLogger(__name__)


class KafkaInboundTransport(BaseInboundTransport):
    """Inbound Transport using Kafka."""

    def __init__(self, host: str, port: int, create_session, **kwargs) -> None:
        """Initialize base queue type."""
        super().__init__("kafka", create_session, **kwargs)
        self.host = host
        self.port = port
        self.config = (
            get_config(self.root_profile.context.settings).inbound
            or InboundConfig.default()
        )
        LOGGER.info(
            f"Setting up kafka inbound transport with configuration: {self.config}"
        )

        self.consumer = AIOKafkaConsumer(
            *self.config.topics,
            bootstrap_servers=self.host,
            **self.config.consumer.dict(),
            ssl_context=ssl.create_default_context()
            if self.config.consumer.ssl_required
            else None,
        )

    async def start(self):
        async with self.consumer:
            async for msg in self.consumer:
                assert isinstance(msg, ConsumerRecord)
                msg = cast(ConsumerRecord[bytes, bytes], msg)
                if msg.value is None:
                    LOGGER.error("Received empty message record")
                    continue

                try:
                    inbound = json.loads(msg.value)
                    payload = base64.urlsafe_b64decode(inbound["payload"])

                    session = await self.create_session(
                        accept_undelivered=False, can_respond=False
                    )

                    async with session:
                        await session.receive(cast(bytes, payload))

                except (JSONDecodeError, KeyError):
                    LOGGER.exception("Received invalid inbound message record")
                except (MessageParseError, WireFormatParseError):
                    LOGGER.exception("Failed to process message")

    async def stop(self):
        await self.consumer.stop()
