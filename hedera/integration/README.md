# Integration Tests

We use `docker compose` to set up the environment, and make use of the [Dockerfile](../docker/Dockerfile) to produce our ACA-Py/Plugin image. To simplify, we have another [Dockerfile](Dockerfile.test.runner) for running those [tests](/tests/).

## Build and run Tests

The integration tests will start following instances:
- 2 ACA-Py agents - Issuer and Holder
- Indy Tails Server (required for revocation support, see [GH repo](https://github.com/bcgov/indy-tails-server))
- Juggernaut container that will execute the tests

```sh
# open a terminal in vs code
cd integration
docker compose build
docker compose up
```
