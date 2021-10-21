"""Kafka Queue configuration."""

from typing import Any, List, Mapping, Union
from pydantic import BaseModel, Extra


def _alias_generator(key: str) -> str:
    return key.replace("-", "_")


class ProducerConfig(BaseModel):
    bootstrap_servers: Union[str, List[str]]

    class Config:
        extra = Extra.allow


class EventsConfig(BaseModel):
    producer: ProducerConfig
    topic_maps: Mapping[str, str]


class InboundConfig(BaseModel):
    group_id: str
    topics: List[str]


class OutboundConfig(BaseModel):
    producer: ProducerConfig
    topic: str


class KafkaConfig(BaseModel):
    events: EventsConfig
    inbound: InboundConfig
    outbound: OutboundConfig

    class Config:
        alias_generator = _alias_generator


DEFAULT_PRODUCER_CONFIG = ProducerConfig(bootstrap_servers="kafka")
DEFAULT_CONFIG = KafkaConfig(
    events=EventsConfig(
        producer=DEFAULT_PRODUCER_CONFIG,
        topic_maps={
            "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
            "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
            "^acapy::record::([^:])?": "acapy-record-$wallet_id",
            "acapy::basicmessage::received": "acapy-basicmessage-received",
        },
    ),
    inbound=InboundConfig(group_id="kafka_queue", topics=["acapy-inbound-message"]),
    outbound=OutboundConfig(
        producer=DEFAULT_PRODUCER_CONFIG, topic="acapy-outbound-message"
    ),
)


def get_config(settings: Mapping[str, Any]) -> KafkaConfig:
    """Retrieve producer configuration from settings."""
    try:
        config_dict = settings["plugin_config"]["kafka_queue"]
        config = KafkaConfig(**config_dict) if config_dict else DEFAULT_CONFIG
    except KeyError:
        return DEFAULT_CONFIG

    return config
