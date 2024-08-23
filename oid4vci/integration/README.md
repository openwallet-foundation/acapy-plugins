# Integration testing for OID4VC Plugin

## Integration Tests

This test suite runs against a test OID4VCI client.

## Interop Tests

This runs automated testing against Credo and Sphereon's OID4VCI Client library.


### Running interop tests

Create a `.env` file with the value `NGROK_AUTHTOKEN` set to your personal ngrok auth token.

An HTTPS endpoint is required for interop testing due to checks performed by the test targets.

Then start up the tests with:

```sh
./run_interop_tests
# Clean up
./run_interop_tests down
```
