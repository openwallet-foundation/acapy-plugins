# did:cheqd Plugin

## Description

This plugin contains the components needed for ACA-Py to use did:cheqd. It also contains the Base class definitions for DIDRegistrar and DIDManager. 

This plugin adds the following endpoints:

- /did/cheqd/create
- /did/cheqd/update
- /did/cheqd/deactivate

## Configuration

The best way to run this plugin is via the DevContainer (configurations provided in the `.devcontainer` folder).

An example configuration for the plugin can be found in [default.yml](./docker/default.yml)

### Running with the configuration

#### Pre-requisites
```bash
# Install the plugin locally
pip install -e .

# If using local DID registrar, set the environment variables
export FEE_PAYER_TESTNET_MNEMONIC="..."
export FEE_PAYER_MAINNET_MNEMONIC="..."
# start the additional services locally
docker-compose -f ./docker/docker-compose.yml up -d

# For first time only, provision the wallet
aca-py provision --arg-file ./docker/provision.yml
```

#### Running the plugin

- If you are using your own DID registrar and resolver, update the urls in [plugin-config.yml](./docker/plugin-config.yml) file.
```bash
# Then start with same wallet config
aca-py start --arg-file ./docker/default.yml
```

## Operations 

The did:cheqd Manager plugin supports following new endpoints

1. POST /did/cheqd/create
1. POST /did/cheqd/update
1. POST /did/cheqd/deactivate

The did:cheqd Manager plugin supports `did:cheqd` for the following existing endpoints
1. POST /anoncreds/schema
1. POST /anoncreds/credential-definition
1. POST /anoncreds/<tbc>
1. GET /resolver/resolve/{did}
1. GET /wallet/did
1. GET /wallet/did/public

## Testing

### Unit Tests

```bash
# Run the tests using following
poetry run pytest .
```
A coverage report is created when ran from the devcontainer. 

### Integration Tests

All integrations tests and configurations are in `integration` folder.
To run the integration tests:

```shell
cd integration
docker compose build
docker compose run tests
docker compose down -v  # Clean up
```

## Deploy

For production use, this plugin should be installed as libraries to an ACA-Py image.

This requires having a Dockerfile and a config file for your agent.

Example Dockerfile:

```Dockerfile
FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.1.0

USER root

# install plugins as binaries
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=cheqd

USER $user
COPY ./configs configs

ENTRYPOINT ["aca-py"]

```

An example config file is provided [here](./docker/default.yml).

Now you can deploy a agent with as many plugins as you want as long as they are declared in your build config file and installed.

``` bash

docker build -f <Dockerfile> --tag did_cheqd_manager .
docker run -it -p 8020:8020 -p 8021:8021 --rm did_cheqd_manager start --arg-file=<config-file> -->

```