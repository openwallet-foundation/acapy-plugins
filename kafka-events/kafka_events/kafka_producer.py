from aries_cloudagent.config.injection_context import InjectionContext
from confluent_kafka import Producer
from .transformer import transform_schema, transform_event
from avro.io import BinaryEncoder, DatumWriter
import io

class KafkaProducer:
    """Kafka event producer."""

    def __init__(self,broker={'bootstrap.servers': 'localhost:9092'}):
        self.producer = Producer(broker)
        self.schemas = []

    def register_schema(self, schema):
        """"""
        avro_schema = transform_schema(schema)
        self.schemas.append(avro_schema)

    def produce(self, event):
        # get schema for kafka event
        event = transform_event(event)
        schema = self.schemas[0] #TODO: find schema for kafka event
        writer = DatumWriter(schema)
        bytes_writer = io.BytesIO()
        encoder = BinaryEncoder(bytes_writer)
        writer.write(event.message, encoder)
        raw_bytes = bytes_writer.getvalue()
        self.producer.produce(event.topic,raw_bytes)
        self.producer.flush()
