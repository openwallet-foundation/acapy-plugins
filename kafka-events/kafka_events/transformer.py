import avro.schema
"""Transformer to transform acapy message schema's to avro schemas."""

def transform_schema(schema):
    # handle type conversions
    # schema = ...
    # TODO: take acapy schema into json for avro parsing
    return avro.schema.parse(schema)

def transform_event(event):
    # convert aca-py topic to kafka topic
    # aca-py topic is domain with state, kafka is kid with message
    # TODO: transform event
    return event