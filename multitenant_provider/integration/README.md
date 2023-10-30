# Integration Tests

Use `docker compose` to set up the environment, and make use of the [Dockerfile](./docker/Dockerfile) to produce our ACA-Py/Plugin image. To simplify, we have a [Dockerfile](Dockerfile.test.runner) for running those [tests](/tests/).

## Build and run Tests

The integration tests will start 1 agent - admin - and a juggernaut container that will execute the tests. Test results will be found in the juggernaut container output. The juggernaut container should close itself down, the logs can be reviewed in the `Docker` view, open `Containers`, open `integration`, right-click the `integration-tests` container and select `View Logs`

```sh
# open a terminal in vs code
cd integration
docker compose build
docker compose up
```
