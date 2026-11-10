## OID4VC ACA-Py Plugin Demo

This is a demo for developers to test and validate the current plugin functionality and to provide a fully working example of the functionality including w3c and ietf status lists. **Do not use for production deployments** 

You will need NGROK to run this demo with a valid Authentication Token
The .env file contains token secrets for the Auth Server

```
cp .env.example .env
export NGROK_AUTHTOKEN=....
docker compose up
```

**Important** The ngrok config only works with the paid version

If you want to try the lightweight zrok draft instead of ngrok, copy `env.zrok.example` to `.env` and run the alternate compose file:

```bash
cp env.zrok.example .env
docker compose -f docker-compose-zrok.yaml up
```

The zrok draft keeps the existing ngrok setup in `docker-compose.yaml` untouched. It assumes you have already reserved stable zrok names for issuer, auth-server, and demo frontend.

#### Setting up zrok Shares

Before running the zrok variant, you need to set up three persistent tunnel shares using the zrok CLI. This is a one-time setup per machine.

1. **Install zrok** (if not already installed):
   ```bash
   # On macOS with Homebrew
   brew install zrok
   
   # Or download from https://github.com/openziti/zrok/releases
   ```

2. **Authenticate with zrok**:
   ```bash
   zrok enable <your-zrok-token>
   ```
   You can get a free zrok account and token at https://zrok.io

3. **Reserve the three tunnel shares** (run these commands once):
   `--unique-name` values are globally unique in zrok's public namespace. Pick names that are unlikely to collide (for example, include your org/user/project prefix).
   ```bash
   # Reserve the issuer endpoint (points to demo issuer on port 8082)
   zrok reserve public --unique-name myteamoid4vcissuer http://localhost:8082
   
   # Reserve the auth-server endpoint (points to auth-server on port 9001)
   zrok reserve public --unique-name myteamoid4vcauthserver http://localhost:9001
   
   # Reserve the demo app endpoint (points to demo-app on port 3000)
   zrok reserve public --unique-name myteamoid4vcdemo http://localhost:3000
   ```

4. **Run the demo with zrok**:
   ```bash
   docker compose --env-file env.zrok.example -f docker-compose-zrok.yaml up
   ```

If you tear the stack down with `docker compose -f docker-compose-zrok.yaml down -v` and Docker later reports a missing network on restart, bring the stack back up with the same compose file and force recreation:

```bash
docker compose --env-file env.zrok.example -f docker-compose-zrok.yaml up --force-recreate --remove-orphans
```

That rebuilds any stale containers that were still pointing at the removed compose network.

The reserved shares will create stable public URLs (based on your unique names), for example:
- `https://myteam-oid4vc-issuer.share.zrok.io` → demo issuer
- `https://myteam-oid4vc-authserver.share.zrok.io` → auth-server
- `https://myteam-oid4vc-demo.share.zrok.io` → demo app frontend

Set the same names in `ISSUER_ZROK_NAME`, `AUTHSERVER_ZROK_NAME`, and `DEMO_ZROK_NAME` in your `.env` file, and update `OID4VCI_ENDPOINT`, `TENANT_ISSUER_BASE_URL`, and `DEMO_PUBLIC_URL` to match the resulting URLs (the demo app's own public auth-server URL is derived from `TENANT_ISSUER_BASE_URL`, no separate variable needed).

#### zrok Reliability

zrok's reserved-share agent can silently lose its underlying OpenZiti circuit while still reporting the share as "active" ([openziti/zrok#1259](https://github.com/openziti/zrok/issues/1259)). Since the container never crashes, Docker's own restart policy won't recover it, and requests will start failing with a `502` from the zrok edge with no other visible symptom. The `zrok-watchdog` service in `docker-compose-zrok.yaml` polls each share's public URL and restarts the affected container when it stops answering. Make sure `DEMO_PUBLIC_URL` (in addition to the other public URL variables above) is set to your actual reserved domain, or the watchdog will poll the wrong URL for the demo share.

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