import logging
from typing import cast

from aiokafka import AIOKafkaConsumer
from aiokafka.structs import ConsumerRecord
from aries_cloudagent.messaging.error import MessageParseError
from aries_cloudagent.transport.error import WireFormatParseError
from aries_cloudagent.transport.inbound.base import BaseInboundTransport


LOGGER = logging.getLogger(__name__)


class KafkaInboundTransport(BaseInboundTransport):
    """Inbound Transport using Kafka."""

    INBOUND_TOPIC = "acapy-inbound-message"
    DEFAULT_GROUP = "acapy"

    def __init__(self, host: str, port: int, create_session, **kwargs) -> None:
        """
        Initialize an inbound HTTP transport instance.

        Args:
            host: Host to listen on
            port: Port to listen on
            create_session: Method to create a new inbound session

        """
        super().__init__("kafka", create_session, **kwargs)
        self.host = host
        self.port = port
        self.consumer = AIOKafkaConsumer(
            self.INBOUND_TOPIC, bootstrap_servers=self.host, group_id=self.DEFAULT_GROUP
        )

    async def start(self):
        async with self.consumer:
            async for msg in self.consumer:
                assert isinstance(msg, ConsumerRecord)
                session = await self.create_session(
                    accept_undelivered=False, can_respond=False
                )
                async with session:
                    try:
                        await session.receive(cast(bytes, msg.value))
                    except (MessageParseError, WireFormatParseError):
                        LOGGER.exception("Failed to process message")

    async def stop(self):
        await self.consumer.stop()
