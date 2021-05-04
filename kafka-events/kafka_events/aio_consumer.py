"""
Producer developed from https://github.com/confluentinc/confluent-kafka-python/blob/master/examples/asyncio_example.py example.
https://www.confluent.io/blog/kafka-python-asyncio-integration/
"""
import asyncio
from confluent_kafka import KafkaException
from threading import Thread
from confluent_kafka import avro
from confluent_kafka.avro import AvroConsumer
from confluent_kafka.avro.serializer import SerializerError
from aries_cloudagent.core.event_bus import Event, EventBus

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

config = {
    'bootstrap.servers': "localhost:9092",
    'schema.registry.url': "http://localhost:8083",
    'group.id':'example_avro',
    'auto.offset.reset': "earliest",
    'topics':["event1","event2"]
    }

class AIOConsumer:
    def __init__(self, context, configs = config, loop=None):
        self._context = context
        self._loop = loop or asyncio.get_event_loop()
        topics = config.pop("topics",[])
        self._consumer = AvroConsumer(config, reader_value_schema=event_schema)
        self._consumer.subscribe(topics)
        self._cancelled = False
        self._poll_thread = Thread(target=self._poll_loop)
        self._poll_thread.start()

    def _poll_loop(self):
        event_bus = self._context.inject(EventBus)
        while not self._cancelled:
            try:
                msg = self._consumer.poll(0.1)
                # There were no messages on the queue, continue polling
                if msg is None:
                    continue
                if msg.error():
                    print("Consumer error: {}".format(msg.error())) #TODO: change to logs
                    continue
                event = Event(msg.topic(), msg.value())
                # event_bus.notify(context,event)
            except SerializerError as e:
                # Report malformed record, discard results, continue polling
                print("Message deserialization failed {}".format(e)) #TODO: change to logs
                continue

    def close(self):
        self._cancelled = True
        self._poll_thread.join()