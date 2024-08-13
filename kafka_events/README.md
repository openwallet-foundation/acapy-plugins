# Kafka Events

This plugin contains the components needed for ACA-Py to use Kafka for inbound
and outbound message queuing and events.

## Installation and Usage

When starting up ACA-Py, load the plugin along with any other startup
parameters.

```sh
aca-py start --plugin kafka_events # ... the remainder of your startup arguments
```

## Plugin configuration

This is an open door to
configure the kafka client to produce and consume records. Kafka has several
configuration beyond the URL of the service.

An example configuration for the plugin can be found in
[`example-config.yml`](https://github.com/hyperledger/aries-acapy-plugins/blob/main/kafka_events/example-config.yml).

### Running with configuration

```shell
aca-py start \
    --plugin kafka_events \
    --plugin-config plugins-config.yaml \
    # ... the remainder of your startup arguments
```

## Consuming DIDComm messages

Messages produced by this plugin contain metadata in addition to the encrypted DIDComm message.
Messages look like:

```json
{
    "service": {"url": "recipient url"},
    "metadata": {...},
    "payload": "encrypted_and_packed_didcomm_message"
}
```

Metadata contain, amongst other things, the plaintext version of the DIDComm message; be cautious and only send the `payload` content over the wire to the DIDComm recipient.
