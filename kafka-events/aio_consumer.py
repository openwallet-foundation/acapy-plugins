import json
import logging
from aiokafka import AIOKafkaConsumer

DEFAULT_CONFIG = {"bootstrap_servers": "kafka", "group_id": "aca-py-events"}
LOGGER = logging.getLogger(__name__)


class AIOConsumer:
    def __init__(self, context, pattern: str, config: dict = None):
        self._context = context
        self._config = config if config else DEFAULT_CONFIG
        self._consumer = None
        self._pattern = pattern

    async def start(self):
        LOGGER.info("Starting the Kafka consuming service")
        self._consumer = AIOKafkaConsumer(**self._config)
        await self._poll_loop()

    async def _poll_loop(self):

        try:
            # Consume messages
            await self._consumer.start()
            self._consumer.subscribe(pattern=self._pattern)
            async for msg in self._consumer:

                await self._read_message(msg)

        except Exception as exc:
            LOGGER.error(f"Init Kafka consumer fails due: {exc}")

    async def _read_message(self, msg):

        event_bus_topic = str(msg.topic).replace("-", "::")

        await self._context.profile.notify(event_bus_topic, json.loads(msg.value))

    async def stop(self):

        LOGGER.info("Stoping Kafka consuming service")
        await self._consumer.stop()
        LOGGER.info("Kafka service is stopped")
