# Redis Events

## Description

This plugin provides mechanism to persist both inbound and outbound messages, deliver messages and webhooks, and dispatch events.

For receiving inbound messages, you have an option to either setup a mediator or a relay [supports [direct response](https://github.com/hyperledger/aries-rfcs/tree/main/features/0092-transport-return-route#aries-rfc-0092-transports-return-route)].

```mermaid
  flowchart LR;
      InboundMsg([Inbound Msg])-->Mediator;
      Mediator-->InboundQueue[(Inbound Queue)];
      InboundQueue-->YourAgent{{Your Agent}};
```

For the relay scenario:

```mermaid
  flowchart LR;
      InboundMsg([Inbound Msg])-->Relay;
      Relay-->InboundQueue[(Inbound Queue)];
      InboundQueue-->YourAgent{{Your Agent}};
```

The `deliverer` service dispatches the outbound messages and webhooks. For the `events`, the payload is pushed to the relevant Redis LIST [for the topic name, refer to [event.event_topic_maps](#plugin-configuration)] and further action is delegated to the controllers.

For the outbound scenario:

```mermaid
  flowchart LR;
      YourAgent{{Your Agent}}-->OutboundQueue[(Outbound Queue)];
      OutboundQueue-->Deliverer;
      Deliverer-->OutboundMsg([Outbound Msg]);
```

The code for the Deliverer and Relay processes are in the `redis_events.v1_0.services.deliverer` and `redis_events.v1_0.services.redis_relay` directories, respectively. The `redis_events.v1_0.status_endpoint` directory contains code for health endpoints that is used by both of these processes.

The `docker` [directory](https://github.com/openwallet-foundation/acapy-plugins/blob/main/redis_events/docker) contains a dockerfile (and instructions) for running ACA-Py with the redis plugin.

## Configuration

The redis events plugin is configured using an external yaml file. An example yaml configuration is:

```yaml
redis_queue:
  connection:
    connection_url: "redis://default:test1234@172.28.0.103:6379"

  ### For Inbound ###
  inbound:
    acapy_inbound_topic: "acapy_inbound"
    acapy_direct_resp_topic: "acapy_inbound_direct_resp"

  ### For Outbound ###
  outbound:
    acapy_outbound_topic: "acapy_outbound"
    mediator_mode: false

  ### For Event ###
  event:
    event_topic_maps:
      ^acapy::webhook::(.*)$: acapy-webhook-$wallet_id
      ^acapy::record::([^:]*)::([^:]*)$: acapy-record-with-state-$wallet_id
      ^acapy::record::([^:])?: acapy-record-$wallet_id
      acapy::basicmessage::received: acapy-basicmessage-received
      acapy::problem_report: acapy-problem_report
      acapy::ping::received: acapy-ping-received
      acapy::ping::response_received: acapy-ping-response_received
      acapy::actionmenu::received: acapy-actionmenu-received
      acapy::actionmenu::get-active-menu: acapy-actionmenu-get-active-menu
      acapy::actionmenu::perform-menu-action: acapy-actionmenu-perform-menu-action
      acapy::keylist::updated: acapy-keylist-updated
      acapy::revocation-notification::received: acapy-revocation-notification-received
      acapy::revocation-notification-v2::received: acapy-revocation-notification-v2-received
      acapy::forward::received: acapy-forward-received
    event_webhook_topic_maps:
      acapy::basicmessage::received: basicmessages
      acapy::problem_report: problem_report
      acapy::ping::received: ping
      acapy::ping::response_received: ping
      acapy::actionmenu::received: actionmenu
      acapy::actionmenu::get-active-menu: get-active-menu
      acapy::actionmenu::perform-menu-action: perform-menu-action
      acapy::keylist::updated: keylist
    deliver_webhook: true
```

The configuration parameters in the above example are:

Connection:

- `redis_queue.connection.connection_url`: This is required and is expected in `redis://{username}:{password}@{host}:{port}` format.

Inbound:

- `redis_queue.inbound.acapy_inbound_topic`: This is the topic prefix for the inbound message queues. Recipient key of the message are also included in the complete topic name. The final topic will be in the following format `acapy_inbound_{recip_key}`
- `redis_queue.inbound.acapy_direct_resp_topic`: Queue topic name for direct responses to inbound message.

Outbound:

- `redis_queue.outbound.acapy_outbound_topic`: Queue topic name for the outbound messages. Used by Deliverer service to deliver the payloads to specified endpoint.
- `redis_queue.outbound.mediator_mode`: Set to true, if using Redis as a http bridge when setting up a mediator agent. By default, it is set to false.

Events:

- `event.event_topic_maps`: Event topic map
- `event.event_webhook_topic_maps`: Event to webhook topic map
- `event.deliver_webhook`: When set to true, this will deliver webhooks to endpoints specified in `admin.webhook_urls`. By default, set to true.

### Plugin deployment

Once the plugin config is defined, it is possible to deploy the plugin inside ACA-Py.

```shell
aca-py start \
    --plugin redis_events.v1_0.redis_queue.events \
    --plugin-config plugins-config.yaml \
    -it redis_events.v1_0.redis_queue.inbound redis 0 -ot redis_events.v1_0.redis_queue.outbound
    # ... the remainder of your startup arguments
```

### Status Endpoints

`Relay` and `Deliverer` service have the following service endpoints available:

- `GET` &emsp; `http://{STATUS_ENDPOINT_HOST}:{STATUS_ENDPOINT_PORT}/status/ready`
- `GET` &emsp; `http://{STATUS_ENDPOINT_HOST}:{STATUS_ENDPOINT_PORT}/status/live`

The configuration for the endpoint service can be provided as following for `relay` and `deliverer`. The API KEY should be provided in the header with `access_token` as key name.

```yaml
environment:
    - STATUS_ENDPOINT_HOST=0.0.0.0
    - STATUS_ENDPOINT_PORT=7001
    - STATUS_ENDPOINT_API_KEY=test_api_key_1
```

### Basic Flow Diagrams

Relay:

```mermaid
  sequenceDiagram
    box Alice
    participant A as Alice
    end
    box Bob
    participant R as Relay
    participant IRQ as Inbound [Redis Queue]
    participant ACA as ACA-PY Agent
    participant ORQ as Outbound [Redis Queue]
    participant D as Deliverer
    end
        A->>R: 
        R->>IRQ: 
        ACA->>IRQ: consume 
        ACA->>ACA: process 
        ACA->>ORQ: 
        D->>ORQ: consume 
        D->>A: 
```

Mediator:

```mermaid
  sequenceDiagram
  box Alice
  participant A as Alice
  participant ACAM as ACA-PY Mediator
  end
  box Bob
  participant IRQ as Inbound [Redis Queue]
  participant ACA as ACA-PY Agent
  participant ORQ as Outbound [Redis Queue]
  participant D as Deliverer
  end
      A->>ACAM: 
      ACAM->>IRQ: 
      ACA->>IRQ: consume
      ACA->>ACA: process
      ACA->>ORQ: 
      D->>ORQ: consume
      D->>A: 
```

Relay - Direct Response:

```mermaid
  sequenceDiagram
    box Alice
    participant A as Alice
    end
    box Bob
    participant R as Relay
    participant IRQ as Inbound [Redis Queue]
    participant ACA as ACA-PY Agent
    participant ORQ as Outbound [Redis Queue]
    participant D as Deliverer
    end
        A->>R: 
        R->>IRQ: 
        ACA->>IRQ: consume 
        ACA->>ACA: process 
        ACA->>IRQ: inbound response 
        R->>IRQ: consume 
        R->>A: 
```
