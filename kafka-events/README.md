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
