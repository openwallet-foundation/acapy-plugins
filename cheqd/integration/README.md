# Integration Tests

All plugins should have a suite of integration tests. We use `docker compose` to set up the environment, and make use of the [Dockerfile](../docker/Dockerfile) to produce our ACA-Py/Plugin image. To simplify, we have another [Dockerfile](Dockerfile.test.runner) for running those [tests](./tests/).

## Build and run Tests

The integration tests will start 2 agents - Issuer and Holder - and a juggernaut container that will execute the tests. Test results will be found in the juggernaut container output. The juggernaut container should close itself down, the logs can be reviewed in the `Docker` view, open `Containers`, open `integration`, right-click the `integration-tests` container and select `View Logs`

```sh
# open a terminal in vs code
cd integration
./run_integration_tests.sh
```

## Postman Tests

We have also included Postman collection (and environment variables) in the [postman](./postman/) folder.

To execute the Postman tests, import both the files into Postman application. Then start the docker environment with `docker compose up -d`. You may have to build the images if you did not run the integration tests before with `docker compose build`.

Then exceute the tests/calls from the Postman application as per the requests descriptions.
