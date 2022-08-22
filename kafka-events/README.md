# Kafka for ACA-PY

This plugin contains the components needed for ACA-Py to use Kafka for inbound
and outbound message queuing and events.

## Installation and Usage

First, install this plugin into your environment.

```sh
$ pip install git+https://github.com/sicpa-dlab/aries-acapy-plugin-kafka-events.git
```

When starting up ACA-Py, load the plugin along with any other startup
parameters.

```sh
$ aca-py start --plugin kafka_queue # ... the remainder of your startup arguments
```

## Plugin configuration

This is an open door to
configure the kafka client to produce and consume records. Kafka has several
configuration beyond the URL of the service. 

The kafka plugin will pull configuration from ACA-Py's plugin config settings.
This enables us to create and use a configuration yaml file and then load it on
startup with ACA-Py. See this PR for more details [Plugin
configuration](https://github.com/hyperledger/aries-cloudagent-python/pull/1226).

An example configuration for the plugin can be found in
[`example-config.yml`](./example-config.yml).

### Running with configuration

```shell
$ aca-py start \
    --plugin kafka_events \
    --plugin-config plugins-config.yaml \
    # ... the remainder of your startup arguments
```
