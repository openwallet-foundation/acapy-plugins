ACA-Py Plugin - Kafka outbound message queue
=======================================

This plugin provides an ACA-Py Kafka event producer interface to a Kafka service.
## Installation and Usage

First, install this plugin into your environment.

```sh
$ pip install git+https://github.com/sicpa-dlab/aries-acapy-plugin-kafka-events.git
```

When starting up ACA-Py, load the plugin along with any other startup
parameters.

```sh
$ aca-py start --arg-file my_config.yml --plugin kafka_queue
```

# Kafka plugin deep dive

## Plugin configuration
Thanks to the feature [Plugin configuration](https://github.com/hyperledger/aries-cloudagent-python/pull/1226), now It is possible to configure plugins via yaml file. This is an open door to configure the kafka client to produce and consume records. Kafka has several configuration beyond the URL of the service. 
It is possible to configure the security to establish communication with the broker, set the timeouts, indicate the consumer groups...
The configuration file for the plugin follows the following structure:

```yaml
kafka_events:

  # General #

  bootstrap_servers: "kafka"
  client_id: "aca-py"
#  request_timeout_ms: 40000
#  connections_max_idle_ms: 540000
#  api_version: "auto"

  ## Security ##

#  security_protocol: "PLAINTEXT"
#  ssl_context: "<ssl_context>"
#  sasl_mechanism: "PLAIN",
#  sasl_plain_password: "<password>"
#  sasl_plain_username: "<username>"
#  sasl_kerberos_service_name: "<service_name>"
#  sasl_kerberos_domain_name: "<domain_name>"
#  sasl_oauth_token_provider: "<token>"

  ### For consumers ###

  consumer-config:
#    group_id: "kafka_events"
#    fetch_max_wait_ms: 500
#    fetch_max_bytes: 52428800 # 50 * 1024 * 1024 = 50MB
#    fetch_min_bytes: 1
#    max_partition_fetch_bytes: 10485761 # 1024 * 1024 = 1MB
#    auto_offset_reset: "latest"
#    enable_auto_commit: True
#    auto_commit_interval_ms: 5000
#    check_crcs: True
#    metadata_max_age_ms: 300000 # 5 * 60 * 1000 = 5 Minutes
#    max_poll_interval_ms: 300000 # 5 * 60 * 1000 = 5 Minutes
#    rebalance_timeout_ms: # empty, no timeout
#    session_timeout_ms: 10000 # 10 * 1000 = 10 Seconds
#    heartbeat_interval_ms: 3000 # 3 * 1000 = 3 Seconds
#    consumer_timeout_ms: 200 # 0'2 Seconds
#    max_poll_records: # empty, no max poll records

  ### For producers ###

  producer-config:
#    metadata_max_age_ms: 300000 # 5 * 60 * 1000 = 5 Minutes
#    compression_type: # empty, 'gzip', 'snappy' or 'lz4' allowed
#    max_batch_size: 16384
#    max_request_size: 1048576,
#    linger_ms: 0,
#    send_backoff_ms: 100 # 0'1 Seconds
```
## Plugin deployment
Once the plugin config is filled up. It is posible to deploy the plugin inside ACA-Py.
```shell
$ aca-py start \
    --plugin kafka_events \
    --plugin-config plugins-config.yaml \
    # ... the remainder of your startup arguments
```

## Plugin workflow
After the command line instantiation, ACA-Py will start with a Kafka consumer for topics that match the pattern `acapy-inbound-.*`  and It will produce every event from the `EventBus` that follows the topic pattern `acapy::outbound::.*`
### Examples
- ACA-Py Kafka Consumer
```sequence
ACAPy -> Kafka Broker: Suscribe to pattern 'acapy-inbound-.*'

External Software->Kafka Broker: Publish record with topic `acapy-inbound-test`

Note left of Kafka Broker: Route the record to suscribers

Kafka Broker -> ACAPy: Send the record 

ACAPy -> ACAPy: Publish the record to the \n EventBus changing the \n topic separators from \n '-', to '::'

```

- ACA-Py Kafka Producer
```sequence
ACAPy -> ACAPy: EventBus suscribe the pattern 'acapy::outbound::message$'\n to produce kafka records

Note right of ACAPy: EventBus notify a new Event with\ntopic 'acapy::outbound::message'

ACAPy -> Kafka Broker: Publish the record to Kafka changing the \n topic separators from'::', to '-'

ACAPy -> ACAPy: Notify via EventBus the status with the topic\n 'acapy::outbound::message::sent_to_external_queue'
```

## HTTP Requests
With the HTTP admin manager, It is posible to stop and start the Kafka interfaces.

- Stop the Kafka Consumer & Producer
```shell
$ curl "http://aca-py:3001/kafka/start"
```

- Start the Kafka Consumer & Producer
```shell
$ curl "http://aca-py:3001/kafka/stop"
```

## Annexed
### Why Kafka?
Kafka details in KafkaEvents


### Authors
Luis Gomez, [Luis-GA](https://github.com/Luis-GA)
Adam Burdett, [burdettadam](https://github.com/burdettadam)
Daniel Bluhm, [dbluhm](https://github.com/dbluhm)
