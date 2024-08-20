"""Redis Queue configuration."""

import logging
from typing import Any, Mapping, Optional

from pydantic import BaseModel

LOGGER = logging.getLogger(__name__)

EVENT_TOPIC_MAP = {
    "^acapy::webhook::(.*)$": "acapy-webhook-$wallet_id",
    "^acapy::record::([^:]*)::([^:]*)$": "acapy-record-with-state-$wallet_id",
    "^acapy::record::([^:])?": "acapy-record-$wallet_id",
    "acapy::basicmessage::received": "acapy-basicmessage-received",
    "acapy::problem_report": "acapy-problem_report",
    "acapy::ping::received": "acapy-ping-received",
    "acapy::ping::response_received": "acapy-ping-response_received",
    "acapy::actionmenu::received": "acapy-actionmenu-received",
    "acapy::actionmenu::get-active-menu": "acapy-actionmenu-get-active-menu",
    "acapy::actionmenu::perform-menu-action": "acapy-actionmenu-perform-menu-action",
    "acapy::keylist::updated": "acapy-keylist-updated",
    "acapy::revocation-notification::received": "acapy-revocation-notification-received",
    "acapy::revocation-notification-v2::received": "acapy-revocation-notification-v2-received",  # noqa: E501
    "acapy::forward::received": "acapy-forward-received",
    "acapy::outbound-message::queued_for_delivery": "acapy-outbound-message-queued-for-delivery",  # noqa: E501
}

EVENT_WEBHOOK_TOPIC_MAP = {
    "acapy::basicmessage::received": "basicmessages",
    "acapy::problem_report": "problem_report",
    "acapy::ping::received": "ping",
    "acapy::ping::response_received": "ping",
    "acapy::actionmenu::received": "actionmenu",
    "acapy::actionmenu::get-active-menu": "get-active-menu",
    "acapy::actionmenu::perform-menu-action": "perform-menu-action",
    "acapy::keylist::updated": "keylist",
}


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class ConnectionConfig(BaseModel):
    """Connection configuration model."""

    connection_url: str

    class Config:
        """Pydantic config."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Default connection configuration."""
        return cls(connection_url="redis://default:test1234@172.28.0.103:6379")


class EventConfig(BaseModel):
    """Event configuration model."""

    event_topic_maps: Mapping[str, str] = EVENT_TOPIC_MAP
    event_webhook_topic_maps: Mapping[str, str] = EVENT_WEBHOOK_TOPIC_MAP
    deliver_webhook: bool = True

    class Config:
        """Pydantic config."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Default event configuration."""
        return cls(
            event_topic_maps=EVENT_TOPIC_MAP,
            event_webhook_topic_maps=EVENT_WEBHOOK_TOPIC_MAP,
            deliver_webhook=True,
        )


class InboundConfig(BaseModel):
    """Inbound configuration model."""

    acapy_inbound_topic: str = "acapy_inbound"
    acapy_direct_resp_topic: str = "acapy_inbound_direct_resp"

    class Config:
        """Pydantic config."""

        alias_generator = _alias_generator
        populate_by_name = True

    @classmethod
    def default(cls):
        """Default inbound configuration."""
        return cls(
            acapy_inbound_topic="acapy_inbound",
            acapy_direct_resp_topic="acapy_inbound_direct_resp",
        )


class OutboundConfig(BaseModel):
    """Outbound configuration model."""

    acapy_outbound_topic: str = "acapy_outbound"
    mediator_mode: bool = False

    @classmethod
    def default(cls):
        """Default outbound configuration."""
        return cls(
            acapy_outbound_topic="acapy_outbound",
            mediator_mode=False,
        )


class RedisConfig(BaseModel):
    """Redis configuration model."""

    event: Optional[EventConfig] = EventConfig.default()
    inbound: Optional[InboundConfig] = InboundConfig.default()
    outbound: Optional[OutboundConfig] = OutboundConfig.default()
    connection: ConnectionConfig

    class Config:
        """Pydantic config."""

        validate_assignment = True

    @classmethod
    def default(cls):
        """Default Redis configuration."""
        return cls(
            event=EventConfig.default(),
            inbound=InboundConfig.default(),
            outbound=OutboundConfig.default(),
            connection=ConnectionConfig.default(),
        )


def process_config_dict(config_dict: dict) -> dict:
    """Add connection to inbound, outbound, event and return updated config."""
    filter = ["inbound", "event", "outbound", "connection"]
    for key, value in config_dict.items():
        if key in filter:
            config_dict[key] = value
    return config_dict


def get_config(settings: Mapping[str, Any]) -> RedisConfig:
    """Retrieve producer configuration from settings."""
    try:
        LOGGER.debug("Constructing config from: %s", settings.get("plugin_config"))
        config_dict = settings["plugin_config"].get("redis_queue", {})
        LOGGER.debug("Retrieved: %s", config_dict)
        config_dict = process_config_dict(config_dict)
        config = RedisConfig(**config_dict)
    except KeyError:
        LOGGER.warning("Using default configuration")
        config = RedisConfig.default()

    LOGGER.debug("Returning config: %s", config.model_dump_json(indent=2))
    LOGGER.debug(
        "Returning config(aliases): %s", config.model_dump_json(by_alias=True, indent=2)
    )
    return config
