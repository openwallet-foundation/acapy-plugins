"""
Producer developed from https://github.com/confluentinc/confluent-kafka-python/blob/master/examples/asyncio_example.py example.
https://www.confluent.io/blog/kafka-python-asyncio-integration/
"""
import asyncio
from confluent_kafka import KafkaException
from threading import Thread
from confluent_kafka import avro
from confluent_kafka.avro import AvroProducer
# Parse Schema used for serializing event class
# user example
event_schema = avro.loads("""
    {
        "namespace": "confluent.io.examples.serialization.avro",
        "name": "User",
        "type": "record",
        "fields": [
            {"name": "name", "type": "string"},
            {"name": "favorite_number", "type": "int"},
            {"name": "favorite_color", "type": "string"}
        ]
    }
""")

config = {'bootstrap.servers': "localhost:9092",
            'schema.registry.url': "http://localhost:8083"}

class AIOProducer:
    def __init__(self, configs = config, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self._producer = AvroProducer(config, default_value_schema=event_schema)
        self._cancelled = False
        self._poll_thread = Thread(target=self._poll_loop)
        self._poll_thread.start()

    def _poll_loop(self):
        while not self._cancelled:
            self._producer.poll(0.1)

    def close(self):
        self._cancelled = True
        self._poll_thread.join()

    async def produce(self, topic, value):
        """
        An awaitable produce method.
        """
        result = self._loop.create_future()

        def ack(err, msg):
            if err:
                self._loop.call_soon_threadsafe(result.set_exception, KafkaException(err))
            else:
                self._loop.call_soon_threadsafe(result.set_result, msg)
        self._producer.produce(topic=topic, value=value, on_delivery=ack)
        return result