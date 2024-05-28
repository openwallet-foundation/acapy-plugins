"""Kafka Queue configuration."""

import logging
from abc import ABC, abstractmethod
from typing import List, Mapping, Optional, Union

from aries_cloudagent.config.base import BaseSettings
from aries_cloudagent.config.plugin_settings import PluginSettings
from aries_cloudagent.config.settings import Settings
from pydantic import BaseModel, Extra

LOGGER = logging.getLogger(__name__)


PLUGIN_KEYS = {"kafka", "kafka-queue"}


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class SecurityProtocol(ABC):
    """Base class for security protocol."""

    SSL_PROTOCOLS = ("SSL", "SASL_SSL")

    @property
    def ssl_required(self) -> bool:
        """Return whether SSL is required."""
        return self.security_protocol in self.SSL_PROTOCOLS

    @property
    @abstractmethod
    def security_protocol(self) -> str:
        """Return the security protocol."""
        pass


class ProducerConfig(BaseModel, SecurityProtocol):
    """Producer configuration."""

    bootstrap_servers: Union[str, List[str]]

    class Config:
        """Configuration for producer."""

        extra = Extra.allow
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(bootstrap_servers="kafka")

    @property
    def security_protocol(self) -> str:
        """Return the security protocol."""
        return self.dict().get("security_protocol")


class EventsConfig(BaseModel):
    """Events configuration."""

    producer: ProducerConfig
    topic_maps: Mapping[str, str]

    class Config:
        """Configuration for events."""

        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
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
    """Consumer configuration."""

    group_id: str

    class Config:
        """Configuration for consumer."""

        extra = Extra.allow
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(group_id="kafka_queue")

    @property
    def security_protocol(self) -> bool:
        """Return the security protocol."""
        return self.dict().get("security_protocol")


class InboundConfig(BaseModel):
    """Inbound configuration."""

    consumer: ConsumerConfig
    topics: List[str]

    class Config:
        """Configuration for inbound."""

        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(consumer=ConsumerConfig.default(), topics=["acapy-inbound-message"])


class OutboundConfig(BaseModel):
    """Outbound configuration."""

    producer: ProducerConfig
    topic: str

    @classmethod
    def default(cls):
        """Return default configuration."""
        return cls(producer=ProducerConfig.default(), topic="acapy-outbound-message")


class KafkaConfig(BaseModel):
    """Kafka configuration."""

    events: Optional[EventsConfig]
    inbound: Optional[InboundConfig]
    outbound: Optional[OutboundConfig]

    @classmethod
    def default(cls):
        """Return default configuration."""
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