import json
import logging

from aiokafka import AIOKafkaProducer

DEFAULT_CONFIG = {"bootstrap_servers": "kafka"}
LOGGER = logging.getLogger(__name__)


class AIOProducer:
    def __init__(self, config: dict = None):
        self._config = config or DEFAULT_CONFIG
        self._producer = None
        self._active = False

    @property
    def active(self):
        return self._active

    @active.setter
    def active(self, x: bool):
        self._active = x

    async def produce(self, topic: str, payload: dict):
        """
        An awaitable produce method.
        """
        if not self._active:
            LOGGER.warning("No active Kafka Producer")
            return
        topic = topic.replace("::", "-")
        try:
            # Produce message
            await self._start()
            LOGGER.info(f"Sending message {payload} with Kafka topic {topic}")
            await self._producer.send_and_wait(topic, str.encode(json.dumps(payload)))

        except Exception as exc:
            LOGGER.error(f"Kafka producer failed sending a message due {exc}")

        finally:
            await self._stop()

    async def _start(self):
        self._producer = AIOKafkaProducer(**self._config)

        await self._producer.start()

    async def _stop(self):
        await self._producer.stop()
