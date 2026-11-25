# Integration Tests

All plugins should have a suite of integration tests. We use `docker compose` to set up the environment, and make use of the [Dockerfile](../docker/Dockerfile) to produce our ACA-Py/Plugin image. To simplify, we have another [Dockerfile](Dockerfile.test.runner) for running those [tests](/tests/).

## Build and run Tests

The integration tests will start 2 agents - bob and alice - and a juggernaut container that will execute the tests. Test results will be found in the juggernaut container output. The juggernaut container should close itself down, the logs can be reviewed in the `Docker` view, open `Containers`, open `integration`, right-click the `integration-tests` container and select `View Logs`

```sh
# open a terminal in vs code
cd integration
docker compose build
docker compose up
```
