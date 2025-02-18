# Hedera plugin demo

This demo serves as an interactive display of the features present in this plugin.
The general flow and interface used are very similar to ACA-Py's very own [demo](https://aca-py.org/latest/demo/), so if you went through it, the experience will be the same.

This demo contains two actors: a credential Issuer (which will also play the role of Verifier) and a Holder.
Each of these actors will have an associated ACA-Py instance. These instances will have Hedera plugin enabled, use their own wallet, and be subscribed to actionable events via webhooks to notify the user (for example, when a new connection was created).

## Notes

- When events trigger, the respective actor gets a log printed on top of their menu - for example, upon connection established, new message, or proof request.
- Credential offers and proof requests are automatically accepted
- Demo agents are set up using docker compose

## Usage

A helper script - `run_demo` was created to abstract away much of the required setup.

To run this script you'll need the following dependencies:
- bash
- curl
- jq
- ngrok (if you wish to make agents publicly accessible)
- docker
- docker-compose

When these are installed, open two different terminal instances and respectively run the following commands inside the `demo/` folder:

#### Issuer terminal
```bash
# (Optional) Set ngrok token env, which will automatically create publicly available agent endpoint
export NGROK_AUTHTOKEN="<CHANGE_ME>"

# Run issuer actor
./run_demo issuer
```

#### Holder terminal
```bash
# Run holder actor
./run_demo holder
```

### Setup
The issuer process have more required setup steps, such as registering a DID on Hedera, creating both a schema and associated credential definition for demo credential.
You can see setup progress in console output.

After setup is done, the issuer terminal will output a QR code (if you wish to connect from mobile wallet) and a JSON object containing the invitation.
JSON object can be pasted into the holder's app to establish a connection - use `Input new invitation` option on holder side.

### Demo flow

- Establish a connection between Issuer and Holder agents
  - Use JSON invitation object or QR code in case of Holder party is a mobile wallet
- (Optional) Send a text message between agents/terminals to demonstrate working connection
  - Message can be sent from both Issuer and Holder parties
- Issue demo credential
  - Initiate the process from Issuer terminal and observe results on Holder side (process is automated)
- Verify demo credential
  - Send a proof request from Issuer terminal and observe logs on Holder side and result appearing in Issuer terminal (process is automated)
  - Verification must be successful
- Revoke demo credential
  - Can be done from Issuer terminal
- Try to verify revoked demo credential
  - Send a proof request from Issuer terminal and observe logs on Holder side and result appearing in Issuer terminal (process is automated)
  - Verification must NOT be successful

### Removing containers after running the demo
Please note that Docker containers are not stopped/removed after closing demo applications.

Once you complete the demo run, please stop and remove containers using docker compose command:
```bash
docker compose down
```

### Action menus

#### Issuer

```text
=== Main Issuer menu ===
    (1)    Issue credential - issue a demo credential to last connected holder
    (2)    Send Proof Request - send demo proof request to last connected holder
    (3)    Send Message - send text message to last connected party
    (4)    Create New Invitation - create new Out Of Band invitation
    (5)    Revoke credential - revoke last issued credential
    (x)    Close demo application - close console app (does not stop demo containers)
 > _  <--- Your input here
```

#### Holder

```text
=== Main Holder menu ===
    (3)    Send message - send text message to last connected party
    (4)    Input new invitation - input Ouf Of Band invitation and establish connection
    (x)    Close demo application - close console app (does not stop demo containers)
 > _  <--- Your input here
```