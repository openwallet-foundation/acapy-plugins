# Integration Tests

Docker Compose starts one ACA-Py agent (`agent`) using the plugin
[Dockerfile](../docker/Dockerfile), plus a [test runner](Dockerfile.test.runner).
The agent loads `x509_certs`. No external ledger is needed.

## Build and run Tests

From this directory:

```sh
docker compose build
docker compose up --exit-code-from tests
docker compose down --volumes
```

The tests cover wallet-backed CSRs, importing and retrieving certificates and
trust anchors, chain verification, deletion, and the default-disabled
self-signed route. CSR signatures are verified locally.

To run against an already-started local agent instead of Compose:

```sh
poetry install
AGENT_URL=http://127.0.0.1:3001 poetry run pytest
```

Use the [integration settings](../docker/integration.yml) with loopback-bound
ports and a dedicated test wallet.
