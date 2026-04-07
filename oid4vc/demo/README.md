## OID4VC ACA-Py Plugin Demo

This is a demo for developers to test and validate the current plugin functionality and to provide a fully working example of the functionality including w3c and ietf status lists. **Do not use for production deployments** 

You will need NGROK to run this demo with a valid Authentication Token
The .env file contains token secrets for the Auth Server

```
cp .env.example .env
export NGROK_AUTHTOKEN=....
docker compose up
```

### Demo Functionality

* Issue credentials via OpendID4VCI 1.0 - JWT, SD-JWT and mDOC
* Present Proof via OpendID4VP - JWT, SD-JWT (Not working, in development)
* Update the status of a JWT or SD-JWT credential
* Refresh an SD-JWT credetial
* Display credential records

### Current Status of the Demo

This demo works with the Bifold wallet and the Paradym wallet (exception of JWT type). Note, for mDOC support in Bifold core you need to import a trusted certificate created from the DID. Support for mDOC in Bifold is under active development.

Verification in the oid4vc plugin is still supporting an earlier draft of OID4VP and won't likely work with any modern wallet.

Overall the demo needs to be refactored due to the additional functionality added to index.js

### Credential Refresh

When a credential is refreshed it is updated and made available to the /credential endpoint.

To retrieve the credential a refresh token is required. In the future, dPOP will also be required.

You will need a mechanism to trigger the refresh in your wallet. One mechanism is to monitor the status of the credential via the credential status list. Bifold supports this option if configured to do so.