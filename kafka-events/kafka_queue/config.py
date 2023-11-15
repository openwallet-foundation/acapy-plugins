"""Kafka Queue configuration."""

import logging
from abc import ABC, abstractmethod
from typing import List, Mapping, Optional, Union

from pydantic import BaseModel, Extra

from aries_cloudagent.config.base import BaseSettings
from aries_cloudagent.config.plugin_settings import PluginSettings
from aries_cloudagent.config.settings import Settings

LOGGER = logging.getLogger(__name__)


PLUGIN_KEYS = {"kafka", "kafka-queue"}


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class SecurityProtocol(ABC):
    SSL_PROTOCOLS = ("SSL", "SASL_SSL")

    @property
    def ssl_required(self) -> bool:
        return self.security_protocol in self.SSL_PROTOCOLS

    @property
    @abstractmethod
    def security_protocol(self) -> str:
        pass


class ProducerConfig(BaseModel, SecurityProtocol):
    bootstrap_servers: Union[str, List[str]]

    class Config:
        extra = Extra.allow
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(bootstrap_servers="kafka")

    @property
    def security_protocol(self) -> str:
        return self.dict().get("security_protocol")


class EventsConfig(BaseModel):
    producer: ProducerConfig
    topic_maps: Mapping[str, str]

    class Config:
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(
            producer=ProducerConfig.default(),
            topic_maps={
                "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
                "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
                "^acapy::record::([^:])?": "acapy-record-$wallet_id",
                "acapy::basicmessage::received": "acapy-basicmessage-received",
            },
        )


class ConsumerConfig(BaseModel, SecurityProtocol):
    group_id: str

    class Config:
        extra = Extra.allow
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(group_id="kafka_queue")

    @property
    def security_protocol(self) -> bool:
        return self.dict().get("security_protocol")


class InboundConfig(BaseModel):
    consumer: ConsumerConfig
    topics: List[str]

    class Config:
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(consumer=ConsumerConfig.default(), topics=["acapy-inbound-message"])


class OutboundConfig(BaseModel):
    producer: ProducerConfig
    topic: str

    @classmethod
    def default(cls):
        return cls(producer=ProducerConfig.default(), topic="acapy-outbound-message")


class KafkaConfig(BaseModel):
    events: Optional[EventsConfig]
    inbound: Optional[InboundConfig]
    outbound: Optional[OutboundConfig]

    @classmethod
    def default(cls):
        return cls(
            events=EventsConfig.default(),
            inbound=InboundConfig.default(),
            outbound=OutboundConfig.default(),
        )


def get_config(root_settings: BaseSettings) -> KafkaConfig:
    """Retrieve producer configuration from settings."""
    assert isinstance(root_settings, Settings)

    settings = PluginSettings()
    for key in PLUGIN_KEYS:
        settings = PluginSettings.for_plugin(root_settings, key, None)
        if len(settings) > 0:
            break

    if len(settings) > 0:
        config = KafkaConfig(**settings)
    else:
        LOGGER.warning("Using default configuration")
        config = KafkaConfig.default()

    LOGGER.debug("Returning config: %s", config.json(indent=2))
    LOGGER.debug("Returning config(aliases): %s", config.json(by_alias=True, indent=2))
    return config
