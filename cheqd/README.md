# did:cheqd Plugin for ACA-Py

## Description

This plugin integrates the [did:cheqd](https://cheqd.io) method with ACA-Py, providing components needed for:

- DID creation, update, and deactivation
- AnonCreds issuance, presentation, and revocation
- JSON-LD Verifiable Credentials issuance, presentation, and revocation
- DID Linked Resources management

The plugin includes base class definitions for `DIDRegistrar` and `DIDManager` to facilitate interactions with the cheqd network.

### Operations 

The did:cheqd Manager plugin supports following endpoints:

#### DID Management

1. POST /did/cheqd/create - Create a new DID on the cheqd network
1. POST /did/cheqd/update - Update an existing DID document
1. POST /did/cheqd/deactivate - Deactivate a DID

#### AnonCreds & Verifiable Credential Support

The plugin enables `did:cheqd` for the following existing endpoints:

1. POST /anoncreds/schema - Create schemas on the cheqd network
1. POST /anoncreds/credential-definition - Create credential definitions
1. POST /anoncreds/revocation/revoke - Revoke credentials
1. GET /resolver/resolve/{did} - Resolve DIDs and DID-linked resources
1. GET /wallet/did - List DIDs in wallet
1. GET /wallet/did/public - Get public DID information

## Features

- **Decentralized Identity Management**: Full DID lifecycle on the cheqd network
- **Verifiable Credentials**: Support for both AnonCreds and JSON-LD credential formats
- **Revocation Support**: Comprehensive credential revocation capabilities
- **DID Linked Resources**: Ability to create and manage resources linked to DIDs

For more details on ACA-Py configuration and usage in Cheqd visit [Cheqd SDK Docs](https://docs.cheqd.io/product/sdk/aca-py).

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

The integration tests will start 2 agents - Issuer and Holder - and a juggernaut container that will execute the tests. Test results will be found in the juggernaut container output. The juggernaut container should close itself down, the logs can be reviewed in the Docker view, open `Containers`, open `integration`, right-click the `integration-tests` container and select `View Logs`.

### Postman Tests

We have also included Postman collection (and environment variables) in the [postman](./integration/postman/) folder.

To execute the Postman tests, import both the files into Postman application. Then start the docker environment with `docker compose up -d`. You may have to build the images if you did not run the integration tests before with `docker compose build`.

Then execute the tests/calls from the Postman application as per the requests descriptions.

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
docker run -it -p 8020:8020 -p 8021:8021 --rm cheqd start --arg-file=<config-file>

```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [Apache License 2.0](../LICENSE).
