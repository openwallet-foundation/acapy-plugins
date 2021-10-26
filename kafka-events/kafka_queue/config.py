"""Kafka Queue configuration."""

import logging
from typing import Any, List, Mapping, Optional, Union
from pydantic import BaseModel, Extra


LOGGER = logging.getLogger(__name__)


def _alias_generator(key: str) -> str:
    return key.replace("_", "-")


class ProducerConfig(BaseModel):
    bootstrap_servers: Union[str, List[str]]

    class Config:
        extra = Extra.allow
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(bootstrap_servers="kafka")


"""
possible webhook events are
'^acapy::webhook::(.*)$' with `topic` groups matching
 - basicmessages
 - problem_report
 - ping
 - actionmenu
 - get-active-menu
 - perform-menu-action
 - forward

 any registered webhook event has access to the `wallet_id` for
 the kafka event being produced. the configuration takes the
 aca-py eventbus matcher with an f-string which will build the
 kafka event being produced.

possible record events are
`^acapy::record::([^:]*)(?:::.*)?$` with `topic` and `state` groups matching
 - connections
    - init
    - invitation
    - request
    - response
    - active
    - error
 - endorse_transaction
    - init
    - transaction_created
    - request_sent
    - request_received
    - transaction_endorsed
    - transaction_refused
    - transaction_resent
    - transaction_resent_received
    - transaction_cancelled
    - transaction_acked
 - issue_credential
    - roposal_sent
    - proposal_received
    - offer_sent
    - offer_received
    - request_sent
    - request_received
    - credential_issued
    - credential_received
    - credential_acked
 - issue_credential_v2_0
    - proposal-sent
    - proposal-received
    - offer-sent
    - offer-received
    - request-sent
    - request-received
    - credential-issued
    - credential-received
    - done
 - issue_credential_v2_0_indy
 - issue_credential_v2_0_ld_proof
 - oob_invitation
    - initial
    - await_response
    - done
 - present_proof
    - proposal_sent
    - proposal_received
    - request_sent
    - request_received
    - presentation_sent
    - presentation_received
    - verified
    - presentation_acked
 - present_proof_v2_0
    - proposal-sent
    - proposal-received
    - request-sent
    - request-received
    - presentation-sent
    - presentation-received
    - done
    - abandoned
 - issuer_cred_rev
    - issued
    - revoked
 - revocation_registry
    - init
    - generated
    - posted
    - active
    - full
"""


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


class InboundConfig(BaseModel):
    group_id: str
    topics: List[str]

    class Config:
        alias_generator = _alias_generator
        allow_population_by_field_name = True

    @classmethod
    def default(cls):
        return cls(group_id="kafka_queue", topics=["acapy-inbound-message"])


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


def get_config(settings: Mapping[str, Any]) -> KafkaConfig:
    """Retrieve producer configuration from settings."""
    try:
        LOGGER.debug("Constructing config from: %s", settings.get("plugin_config"))
        config_dict = settings["plugin_config"].get("kafka-queue", {})
        LOGGER.debug("Retrieved: %s", config_dict)
        config = KafkaConfig(**config_dict)
    except KeyError:
        LOGGER.warning("Using default configuration")
        config = KafkaConfig.default()

    LOGGER.debug("Returning config: %s", config.json(indent=2))
    LOGGER.debug("Returning config(aliases): %s", config.json(by_alias=True, indent=2))
    return config
