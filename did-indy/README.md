# acapy-did-indy

## Overview

This plugin provides the following components:

- A did:indy resolver
- A did:indy registar
- Routes for creating a did:indy

The plugin relies on the [DID Indy Driver](https://github.com/Indicio-tech/did-indy-py) to support automatic transaction endoresment. The driver is a seperate container. For example, using docker-compose:

```docker
driver:
    platform: linux/arm64
    image: ghcr.io/indicio-tech/did-indy-py:py3.12-nightly
    # driver configuration here (see below)
    healthcheck:
      test: python healthcheck.py localhost 80
      start_period: 10s
      interval: 10s
      timeout: 5s
      retries: 5

# other containers, e.t.c.

agent:
    image: ghcr.io/openwallet-foundation/acapy-agent
    entrypoint: >
      /bin/sh -c 'aca-py "$$@"' --
    command: >
      start
        --inbound-transport http 0.0.0.0 3000
        --outbound-transport http
        --endpoint http://agent:3000
        --admin 0.0.0.0 3001
        --admin-insecure-mode
        # ...
    depends_on:
      driver:
        condition: service_healthy
```

Without the driver, the plugin is only able to support DID resolution.

See the demo for an example scenario where a did:indy DID is created to sign an Open Badges v3 credential.

## Configuration

### Driver

The DID Indy Driver is used to register DIDs. The plugin acts as a client to the driver, calling the driver's endpoints. In order to do so, the `ISSUER` environment variable in the driver must match the `driver_uri` plugin variable:

```docker
driver:
    platform: linux/arm64
    image: ghcr.io/indicio-tech/did-indy-py:py3.12-nightly
    environment:
        ISSUER: http://driver
    # more config here...

agent:
    image: ghcr.io/openwallet-foundation/acapy-agent
    ...
    entrypoint: >
      /bin/sh -c 'aca-py "$$@"' --
    command: >
      start
        --inbound-transport http 0.0.0.0 3000
        --outbound-transport http
        --endpoint http://agent:3000
        --admin 0.0.0.0 3001
        --admin-insecure-mode
        # ...
        --plugin acapy_did_indy
        --plugin-config-value acapy_did_indy.driver_uri=http://driver
```

#### Authorization
It is recommended that the driver have an API key, which can be configured using the `ADMIN_API_KEY` environment variable. The `AUTH` environment variable must be set to `"api-key"`. In the plugin, the same API key must be specified using the `api_key` plugin variable. This looks like this:
```docker
driver:
    platform: linux/arm64
    image: ghcr.io/indicio-tech/did-indy-py:py3.12-nightly
    # ...
    environment:
        ISSUER: http://driver 
        AUTH: "api-key"
        ADMIN_API_KEY: <YOUR-API-KEY>

# other containeres, e.t.c.

agent:
    image: ghcr.io/openwallet-foundation/acapy-agent
    # ...
    entrypoint: >
      /bin/sh -c 'aca-py "$$@"' --
    command: >
      start
        --inbound-transport http 0.0.0.0 3000
        --outbound-transport http
        --endpoint http://agent:3000
        --admin 0.0.0.0 3001
        --admin-insecure-mode
        # ...
        --plugin acapy_did_indy
        --plugin-config-value acapy_did_indy.driver_uri=http://driver
        --plugin-config-value acapy_did_indy.api_key=<YOUR-API-KEY>
```

#### Driver Ledgers
The driver must have access to relevant ledgers. These are specified in a toml file in the following format:

```toml
[[ledgers]]
# /path/to/ledgers.toml
namespace = <NAMESPACE>
url = <GENESIS-FILE-URL>
seed = <SEED>
```

For example:
```toml
# /path/to/ledgers.toml
[[ledgers]]
namespace = "indicio:test"
url = "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis"
seed = <SEED>

[[ledgers]]
namespace = "indicio:demo"
url = "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_demonet_genesis"
seed = <SEED>
```

These are then loaded into the driver as a volume:
```docker
driver:
    platform: linux/arm64
    image: ghcr.io/indicio-tech/did-indy-py:py3.12-nightly
    volumes:
      - "/path/to/ledgers.toml:/run/secrets/ledgers.toml:z"
    environment:
        # environment variables here
```

### Plugin Ledgers

By default, the plugin fetches the DID Indy ledger configuration from the driver. This is strongly recommended, as it guarantees compatibility between the plugin and the driver. 

However, in cases where only DID resolution functionality is desired, it is possible to provide ledger configuration directly to the plugin. To do this, the `ledgers_from_driver` plugin variable must be set to `False`.

Additionally, a namespace mapping must be provided. This mapping informs the resolver how to determine a network from a namespace. For example, this config value would tell the resolver that the `indicio:test` namespace has genesis txns available at a given URL (using command line argument syntax described in more detail below):

```sh
aca-py start \
    -it http 0.0.0.0 3000
    # etc etc ...
    --plugin acapy_did_indy
    --plugin-config-value acapy_did_indy.ledgers_from_driver=False
    --plugin-config-value acapy_did_indy.ledgers."indicio:test"=https://...
    --plugin-config-value acapy_did_indy.ledgers."indicio:demo"=https://...
```

### Providing Ledger Configuration for the Plugin

To configure the plugin with these parameters, there are three potential paths:

> Note: newlines and comments added for demonstration purposes; this may not work as is depending on where you're using it

#### Command line argument

```sh
aca-py start
    -it http 0.0.0.0 3000
    # etc etc ...
    --plugin acapy_did_indy  # load the plugin itself
    --plugin-config-value acapy_did_indy.ledgers_from_driver=False
    --plugin-config-value acapy_did_indy.ledgers."indicio:test"=https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis
    --plugin-config-value acapy_did_indy.ledgers."indicio:demo"=https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_demonet_genesis
```

Or, the shorthand:

```sh
aca-py start \
    -it http 0.0.0.0 3000
    # etc etc ...
    --plugin acapy_did_indy  # load the plugin itself
    -o acapy_did_indy.ledgers_from_driver=False
    -o acapy_did_indy.ledgers."indicio:test"=https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis
    -o acapy_did_indy.ledgers."indicio:demo"=https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_demonet_genesis
```


#### Plugin Config file

A separate plugin config file may be used:

```yaml
# my-plugin-config.yaml

acapy-did-indy:
    ledgers:
        indicio:test: https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis
        indicio:demo: https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_demonet_genesis

# Other plugin configurations etc etc ...
```

And then loaded into ACA-Py on startup:

```sh
aca-py start
    -it http 0.0.0.0 3000
    # Other args etc etc ...
    --plugin acapy_did_indy  # load the plugin itself
    --plugin-config my-plugin-config.yaml
```
