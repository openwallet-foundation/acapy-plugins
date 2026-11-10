## OID4VC ACA-Py Plugin Demo

This demo uses the reference authorization server ([`../auth_server`](../auth_server)).
For the same demo with Keycloak as the authorization server, see
[`../demo-keycloak`](../demo-keycloak/README.md).

This is a demo for developers to test and validate the current plugin functionality and to provide a fully working example of the functionality including w3c and ietf status lists. **Do not use for production deployments** 

You will need NGROK to run this demo with a valid Authentication Token
The .env file contains token secrets for the Auth Server. `TENANT_SECRET` (the issuer's client
secret at the Auth Server) must be at least 32 characters; the Auth Server rejects shorter ones.

```
cp .env.example .env
export NGROK_AUTHTOKEN=....
docker compose up
```

**Important** The ngrok config only works with the paid version

### Demo Functionality

* Issue credentials via OpendID4VCI 1.0 - JWT, SD-JWT and mDOC
* Present Proof via OpendID4VP - JWT, SD-JWT (Not working, in development)
* Update the status of a JWT or SD-JWT credential
* Refresh an SD-JWT credential
* Display credential records

### Current Status of the Demo

This demo works with the Bifold wallet and the Paradym wallet (exception of JWT type). Note, for mDOC support in Bifold core you need to import a trusted certificate created from the DID. Support for mDOC in Bifold is under active development.

Verification in the oid4vc plugin is still supporting an earlier draft of OID4VP and won't likely work with any modern wallet.

Overall the demo needs to be refactored due to the additional functionality added to index.js

### Credential Refresh

When a credential is refreshed it is updated and made available to the /credential endpoint.

To refresh an SD-JWT credential from the demo:

1. On the Issue page, choose SD-JWT and tick **Refresh Credential**.
2. Check the **Refresh ID** (required). It is pre-filled with the Refresh ID of the last SD-JWT
   credential the demo offered since the demo app started; the issuance output shows it as
   `refresh_id`.
3. Change the credential data if needed and submit. The page confirms the refresh, or shows why it
   failed.
4. Refresh the credential in the wallet.

Until a refresh has been submitted, the wallet's credential request is rejected, even with a valid
token.

To retrieve the credential a refresh token is required. In the future, dPOP will also be required.

You will need a mechanism to trigger the refresh in your wallet. One mechanism is to monitor the status of the credential via the credential status list. Bifold supports this option if configured to do so.
