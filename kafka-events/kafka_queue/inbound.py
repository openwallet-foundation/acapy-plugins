import base64
import json
from json import JSONDecodeError
import logging
from typing import cast

from aiokafka import AIOKafkaConsumer
from aiokafka.structs import ConsumerRecord
from aries_cloudagent.messaging.error import MessageParseError
from aries_cloudagent.transport.error import WireFormatParseError
from aries_cloudagent.transport.inbound.base import BaseInboundTransport

from . import get_config


LOGGER = logging.getLogger(__name__)


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
        config = get_config(self.root_profile.context.settings).inbound
        self.consumer = AIOKafkaConsumer(
            *config.topics, bootstrap_servers=self.host, group_id=config.group_id
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
