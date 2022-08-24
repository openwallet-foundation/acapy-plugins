from aries_cloudagent.config.settings import Settings

from kafka_queue.config import InboundConfig, OutboundConfig, EventsConfig
from kafka_queue import config

DUMMY_INBOUND_CONFIG = {"group-id": "some-group-id", "topics": []}
DUMMY_OUTBOUND_CONFIG = None
DUMMY_EVENTS_CONFIG = None


def test_get_config_tries_all_config_keys():
    # given
    # trick to force key ordering in test
    config.PLUGIN_KEYS = ["kafka", "kafka-queue"]
    settings = {
        "plugin_config": {
            "kafka-queue": {
                "events": DUMMY_EVENTS_CONFIG,
                "inbound": DUMMY_INBOUND_CONFIG,
                "outbound": DUMMY_OUTBOUND_CONFIG,
            }
        }
    }

    # when
    plugin_config = config.get_config(Settings(settings))

    # then
    assert plugin_config.inbound.group_id == "some-group-id"


def test_get_config_falls_back_to_default():
    # given
    settings = {"plugin_config": {}}

    # when
    plugin_config = config.get_config(Settings(settings))

    # then
    assert plugin_config.inbound == InboundConfig.default()
    assert plugin_config.outbound == OutboundConfig.default()
    assert plugin_config.events == EventsConfig.default()
