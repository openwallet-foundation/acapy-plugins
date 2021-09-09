import logging
from typing import Any, Mapping, cast

from aries_cloudagent.config.settings import Settings

from aiokafka import AIOKafkaConsumer
from aiokafka.structs import ConsumerRecord
from aries_cloudagent.messaging.error import MessageParseError
from aries_cloudagent.transport.error import WireFormatParseError
from aries_cloudagent.transport.inbound.base import BaseInboundTransport


LOGGER = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "group_id": "kafka_queue",
    "inbound_topics": [
        "acapy-inbound-message",
    ],
}


def get_config(settings: Settings) -> Mapping[str, Any]:
    """Retrieve consumer configuration from settings."""
    try:
        consumer_conf = (
            settings["plugin_config"]["kafka_queue"]["consumer-config"]
            or DEFAULT_CONFIG
        )
    except KeyError:
        consumer_conf = DEFAULT_CONFIG

    return consumer_conf


class KafkaInboundTransport(BaseInboundTransport):
    """Inbound Transport using Kafka."""

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
        config = get_config(self.root_profile.get("settings", {}))
        self.consumer = AIOKafkaConsumer(
            **config.get("inbound_topics"),
            bootstrap_servers=self.host,
            group_id=config.get("consumer_group_id")
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
