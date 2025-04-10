# Hedera plugin

## Description

This plugin provides components for adding [Hedera DID method](https://github.com/hashgraph/did-method) and AnonCreds registry support for ACA-Py.

### Structure
Under the hood, the plugin consists from following core components:
- Hedera DID
  - HederaDIDResolver (implementation of [BaseDIDResolver](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/resolver/base.py#L70) interface)
  - HederaDIDRegistrar
- HederaAnonCredsRegistry (implementation of both [BaseAnonCredsResolver](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/anoncreds/base.py#L109) and [BaseAnonCredsRegistrar](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/anoncreds/base.py#L141) interfaces)

### API updates

Hedera plugin aims to add Hedera DID support to existing ACA-Py flows, without bringing completely new functionality or API.

The plugin adds a new endpoint for creating Hedera DID:
- `POST /hedera/did/register`

Other operations with Hedera DID and AnonCreds registry supported via existing ACA-Py endpoints:
- `POST /anoncreds/schema`
- `POST /anoncreds/credential-definition`
- `POST /anoncreds/revocation/revoke`
- `GET /resolver/resolve/{did}`
- `GET /wallet/did`
- `GET /wallet/did/public`

## Demo

The repo contains an interactive demo of ACA-Py + Hedera plugin that can be used to test Hedera DID and AnonCreds Registry functionality.

Please see corresponding [demo folder and README](https://github.com/openwallet-foundation/acapy-plugins/tree/main/hedera/demo)

## Usage

### Prerequisites

- Python 3.12+

### Configuration

- The plugin requires following Hedera-specific configuration to be provided:
  - Hedera network
    - High-level options from publicly available Hedera networks: "mainnet", "testnet" and "previewnet"
  - Hedera Operator configuration
    - Includes Hedera Operator ID and private key
    - Used for Hedera network integration and paying fees
    - Can be obtained by creating developer account on [Hedera Dev Portal](https://portal.hedera.com/)
- The plugin works only with `askar-anoncreds` wallet type

An example configuration for the plugin can be found in [plugins-config.yml](https://github.com/openwallet-foundation/acapy-plugins/blob/main/hedera/docker/plugins-config.yml)

You can also use environment variables to configure the plugin:
- `HEDERA_NETWORK`
- `HEDERA_OPERATOR_ID`
- `HEDERA_OPERATOR_KEY`

### Deployment

For production use, this plugin should be installed as library to an ACA-Py image.

This requires having a Dockerfile and a config file for your agent.

Simple example of Dockerfile:

```Dockerfile
FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.2.2

...

USER root

# install plugins as binaries
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=hedera

...

USER $user
COPY ./configs configs

ENTRYPOINT ["aca-py"]

```

More complete example (including complete dependencies setup) can be found [in docker folder](https://github.com/openwallet-foundation/acapy-plugins/blob/main/hedera/docker/Dockerfile) 

### Create a DID

Process of creating Hedera DID is different comparing to DID Methods that are natively supported by ACA-Py, despite having the same API structure.

To create new Hedera DID, you need to use a specific endpoint added by the plugin: `POST /hedera/did/register`

The endpoint accepts following set of parameters:
```
key_type - Type of DID owner key to create (only a Ed25519 is supported for now)
seed - DID owner key seed
```

#### Example request
```
curl -X 'POST' \
  '{acapy_url}/hedera/did/register' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "key_type": "Ed25519"
}'
```

#### Example response
```json
{
  "did": "did:hedera:testnet:zFQ5MrvqeoBzvCJJFUopRH7jfcAzCdD5ntBc1KnrAZ8F9_0.0.5466776",
  "verkey": "FQ5MrvqeoBzvCJJFUopRH7jfcAzCdD5ntBc1KnrAZ8F9",
  "key_type": "ed25519"
}
```

## Development

The best way to develop and manually test this plugin is to use the [Dev Container](https://containers.dev/) with configurations provided in the `.devcontainer` folder.
Recommended tool for running Dev Containers is [Visual Studio Code](https://code.visualstudio.com/).

- Make sure that Dev Container extension for VS Code is installed
- Open plugin folder in VS Code, see "open dev container" prompt and accept
- Dev container will be built, installing all necessary packages (plugin itself, supported ACA-Py version and other dependencies)
- Once container is ready, you can use `Run/Debug Plugin` configuration in VS code to run ACA-Py along with the plugin
  - You can use Swagger page at http://localhost:3001/api/doc#/ to manually test an API. However, using tools such as [Postman](https://www.postman.com/) is more convenient
  - Local ACA-Py instance is configured to use [multitenancy](https://aca-py.org/latest/features/Multitenancy/), so testing multiple agents and agent-to-agent integration is possible

## Lint and formatting

The project uses [Ruff](https://docs.astral.sh/ruff/) as a linter and code formatter

Run check:
```bash
poetry run ruff check
```

Run check with auto-fix for fixable lint errors:
```bash
poetry run ruff check --fix
```

Run code formatting:
```bash
poetry run ruff format
```

## Unit tests

Unit tests are hosted under src folder: `hedera/tests`

Run tests:
```bash
poetry run pytest
```
A coverage report is created when ran from the devcontainer. 

## Integration tests

Integration tests and configurations are hosted in `integration` folder.

See corresponding [README](https://github.com/openwallet-foundation/acapy-plugins/blob/main/hedera/integration/README.md) for details.
