import json
from aries_cloudagent.core.event_bus import Event, EventBus
import logging
from aiokafka import AIOKafkaConsumer
import asyncio
import threading

DEFAULT_CONFIG = {"bootstrap_servers": "kafka", "group_id": "aca-py-events"}
LOGGER = logging.getLogger(__name__)


class AIOConsumer:
    def __init__(self, profile, pattern: str, config: dict = None):
        self._profile = profile
        self._config = config or DEFAULT_CONFIG
        self._consumer = None
        self._pattern = pattern
        self._loop = None

    async def start(self):
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
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.start())
            self._loop.close()
        except Exception:
            LOGGER.warning("Kafka consumer stopped")

    def start_thread(self):
        threading.Thread(target=self._sync_start).start()

    async def _read_message(self, msg):

        event_bus_topic = str(msg.topic).replace("-", "::")
        await self._profile.notify(event_bus_topic, json.loads(msg.value))

    def stop(self):
        try:
            self._loop.stop()
        except Exception as e:
            LOGGER.error("Stopping consumer: {}".format(e))
