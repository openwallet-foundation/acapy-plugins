import json
from aries_cloudagent.core.event_bus import Event, EventBus
import logging
from aiokafka import AIOKafkaConsumer
import asyncio
import threading

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

    def _sync_start(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.run_until_complete(self.start())
        loop.close()

    def start_thread(self):
        threading.Thread(target=self._sync_start).start()

    async def _read_message(self, msg):

        event_bus_topic = str(msg.topic).replace("-", "::")
        event_bus = self._context.inject(EventBus)
        event = Event(event_bus_topic, json.loads(msg.value))
        await event_bus.notify(self._context, event)

    async def stop(self):

        LOGGER.info("Stoping Kafka consuming service")
        await self._consumer.stop()
        LOGGER.info("Kafka service is stopped")
