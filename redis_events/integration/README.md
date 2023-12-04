# Integration Tests

We use `docker compose` to set up the environment, and make use of the main dockefile in the docker directory [Dockerfile](../docker/Dockerfile), and a similar dockerfile in integration driectory [Dockerfile](../integration/Dockerfile), which has an additional plugin basic_messages. This is used to persist message history for better testing. To simplify, we have another [Dockerfile](Dockerfile.test.runner) for running those [tests](/tests/).

## Build and run Tests

The integration tests will start 2 agents - faber and alice - and a juggernaut container that will execute the tests. Test results will be found in the juggernaut container output. The juggernaut container should close itself down, the logs can be reviewed in the `Docker` view, open `Containers`, open `integration`, right-click the `integration-tests` container and select `View Logs`

```sh
# open a terminal in vs code
cd integration
docker compose build
docker compose up
```
