# did:cheqd Plugin

## Description

This plugin contains the components needed for ACA-Py to use [did:cheqd](https://cheqd.io) method for did creation and Anoncreds issuance, presentation and revocation. It also contains the Base class definitions for `DIDRegistrar` and `DIDManager`. 

### Operations 

The did:cheqd Manager plugin supports following new endpoints:

1. POST /did/cheqd/create
1. POST /did/cheqd/update
1. POST /did/cheqd/deactivate

The did:cheqd Manager plugin supports `did:cheqd` for the following existing endpoints:

1. POST /anoncreds/schema
1. POST /anoncreds/credential-definition
1. POST /anoncreds/revocation/revoke
1. GET /resolver/resolve/{did}
1. GET /wallet/did
1. GET /wallet/did/public

## Developer Notes

The best way to develop and test this plugin is to use the DevContainer configured in this repository (configurations provided in the `.devcontainer` folder).

- Open devcontainer in VS Code.
- Python and all dependencies will be loaded.
- Poetry will be loaded and configured, dependencies will be installed.
- Docker and Docker Compose will be available.

## Configuration

- The plugin expects a DID Registrar and a DID Resolver URL to be provided. It is recommended that the registrar and resolver are run locally. The URLs can be passed via `plugin-config.yml`.
- The plugin works only with `askar-anoncreds` wallet type.
- Using a Postgres DB as wallet storage type is also recommended.

### Running with the configuration

An example configuration for the plugin can be found in [default.yml](./docker/default.yml)

#### Pre-requisites
```bash
# Install the plugin locally
pip install -e .

# If using local Cheqd DID registrar, set the environment variables
export FEE_PAYER_TESTNET_MNEMONIC="..."
export FEE_PAYER_MAINNET_MNEMONIC="..."
# start the registrar, resolver and postgres-db services locally, if needed
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

## Testing

### Unit Tests

```bash
# Run the tests using following
poetry run pytest
```
A coverage report is created when ran from the devcontainer. 

### Integration Tests

All integrations tests and configurations are in `integration` folder.
To run the integration tests:

```shell
cd integration
./run_integration_tests.sh
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

docker build -f <Dockerfile> --tag cheqd .
docker run -it -p 8020:8020 -p 8021:8021 --rm cheqd start --arg-file=<config-file> -->

```
