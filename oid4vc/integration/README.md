# OID4VC Integration Tests

Integration tests for OpenID4VC v1 flows implementing the pattern:
**ACA-Py Issues → Credo/Sphereon Receives → Credo Presents → ACA-Py Verifies**

> **Development status notice:** The OID4VC plugin is under active development.
> When validating changes, **run conformance tests first** (see
> [Testing Against the OIDF Conformance Suite](#testing-against-the-oidf-conformance-suite))
> before running the interop or manual tests against the plugin itself. Conformance
> tests exercise the standard behaviour expected by the specification, making it
> easier to distinguish regressions in the plugin from pre-existing limitations.

---

## Architecture

This test suite validates complete OID4VC v1 flows with three components:

1. **ACA-Py Issuer** – Issues both `mso_mdoc` and SD-JWT credentials via OID4VCI
2. **Credo / Sphereon Holder/Verifier** – Receives credentials from ACA-Py, then presents them using OID4VC v1 support
3. **ACA-Py Verifier** – Validates presentations using the OID4VP plugin

## Credential Types Tested

| Format identifier | Spec | Notes |
|---|---|---|
| `mso_mdoc` | ISO 18013-5 | Mobile driving licences and ID cards |
| `vc+sd-jwt` | [IETF SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.txt) | Selective-disclosure JWT; uses `vct` claim and `typ: vc+sd-jwt` header |
| `jwt_vc_json` | [W3C VCDM 1.1](https://www.w3.org/TR/vc-data-model/) encoded as JWT | W3C Verifiable Credential wrapped in a plain JWT; uses `vc.type` / `@context` |

> **SD-JWT format note:** This plugin implements the **IETF SD-JWT VC** format
> (`vc+sd-jwt`, `draft-ietf-oauth-sd-jwt-vc`), **not** a W3C VCDM SD-JWT
> variant.  Credential configurations must supply a `vct` string in
> `format_data` rather than `@context` / `type`.  Wallets that only handle the
> W3C SD-JWT profile will not be compatible.

---

## Testing Against the OIDF Conformance Suite

> **Recommended first step.** The OIDF Conformance Suite is an independent,
> specification-derived test harness.  Running it first gives a clean signal
> about what the plugin does or does not yet implement before introducing
> interoperability variables.

The conformance environment is activated with the `conformance` Docker Compose
profile and is managed by `run-conformance-tests.sh`.

### First-run build note

The conformance server is built from the
[OpenID Foundation conformance-suite](https://gitlab.com/openid/conformance-suite)
source using Maven.  **The very first build takes 15–20 minutes** because Maven
downloads all dependencies.  Subsequent runs use Docker layer cache and complete
in under a minute.

### Running all conformance tests

```bash
./run-conformance-tests.sh run
```

This command:

1. Builds the OIDF conformance server image (Java/Maven, cached after first run)
2. Starts MongoDB, the conformance server, ACA-Py issuer & verifier, and a TLS
   reverse proxy (required by the HAIP profile's HTTPS mandate)
3. Runs `conformance/setup_acapy.py` to configure DIDs, credential definitions,
   and trust anchors in ACA-Py
4. Runs `conformance/run_conformance.py` to exercise the full test plan via the
   conformance REST API
5. Writes results to `test-results/conformance-junit.xml`
6. Tears down all conformance containers

### Running a specific scope

```bash
# OID4VCI issuer plan only
./run-conformance-tests.sh issuer

# OID4VP verifier plan only
./run-conformance-tests.sh verifier
```

### Other conformance commands

| Command | Description |
|---|---|
| `./run-conformance-tests.sh build` | Build images without running tests |
| `./run-conformance-tests.sh setup` | Start services and configure ACA-Py only |
| `./run-conformance-tests.sh pytest` | Run pytest conformance wrappers (requires services up) |
| `./run-conformance-tests.sh results` | Print a summary of the latest JUnit XML results |
| `./run-conformance-tests.sh logs [service]` | Tail logs (default: `conformance-runner`) |
| `./run-conformance-tests.sh status` | Show status of conformance containers |
| `./run-conformance-tests.sh clean` | Stop containers and remove volumes |

### Conformance environment variables

| Variable | Default | Description |
|---|---|---|
| `CONFORMANCE_SUITE_BRANCH` | `master` | Git branch/tag of the conformance suite to build |
| `CONFORMANCE_SCOPE` | `all` | Test scope: `all`, `issuer`, or `verifier` |
| `COMPOSE_PROJECT_NAME` | `oid4vc-integration` | Docker Compose project name |

Example – run against a pinned conformance suite release:

```bash
CONFORMANCE_SUITE_BRANCH=release-v6.0 ./run-conformance-tests.sh run
```

### Accessing the conformance UI during a run

To inspect test results interactively while services are up, expose the
conformance server to your host by adding an override file (do **not** commit
port overrides to `docker-compose.yml`):

```yaml
# docker-compose.override.yml  (local only, git-ignored)
services:
  conformance-server:
    ports:
      - "8443:8443"
```

Then open `https://localhost:8443` in your browser (accept the self-signed
certificate).

---

### Testing your own SDK or agent against the conformance suite

The conformance suite can play **either role** depending on what you are testing:

| What you are testing | Conformance suite role | Your SDK role |
|---|---|---|
| An **issuer** you are building | Acts as the wallet — calls your endpoints | Issuer (needs a public tunnel) |
| A **wallet receiving** credentials | Acts as the issuer — your wallet calls it | Wallet (needs to reach the suite) |
| A **wallet presenting** credentials | Acts as the verifier — sends a presentation request to your wallet | Wallet (needs to reach the suite) |
| A **verifier** you are building | Acts as the wallet/holder — presents to your verifier | Verifier (needs a public tunnel) |

> **Reference:** [OIDF Conformance Suite (GitLab)](https://gitlab.com/openid/conformance-suite) ·
> [OID4VCI 1.0 spec](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) ·
> [OID4VP 1.0 spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) ·
> [HAIP profile](https://openid.net/specs/openid-4-verifiable-credential-issuance-haip-1_0.html)

---

#### Testing a wallet SDK (conformance suite acts as issuer)

This is the scenario for a mobile wallet: the conformance suite issues
credentials and runs the OID4VCI protocol; your wallet connects to it,
requests a credential, and the suite verifies the wallet behaved correctly.

**Traffic flow:**

```
 Mobile wallet (your SDK on a phone / simulator)
     │  discovers issuer metadata at https://myconformanceserver.share.zrok.io
     │  requests credential
     ▼
 zrok  (https://myconformanceserver.share.zrok.io)
     ▼
 conformance-server  (https://localhost:8443)
     │  verifies the wallet's request matches the spec
     │  issues the credential
     ▼
 Mobile wallet receives credential
```

Your wallet SDK does **not** need a tunnel — it initiates all connections.
Only the conformance server needs to be publicly reachable.

##### Step 1 — Install and enable zrok

```bash
# macOS
brew install openziti/ziti/zrok

# Linux — download the latest binary:
# https://github.com/openziti/zrok/releases/latest
```

Create a free account at **[zrok.io](https://zrok.io)**, copy your token, then:

```bash
zrok enable <your-token>
```

> Already have zrok set up?  Skip to Step 2.

##### Step 2 — Reserve a tunnel for the conformance server

```bash
# Naming rules: lowercase alphanumeric only, 4–32 characters.
zrok reserve public --unique-name "myconformanceserver" https://localhost:8443
```

Note the printed URL (e.g. `https://myconformanceserver.share.zrok.io`).

##### Step 3 — Set the URL in .env

```bash
cp example.env .env   # only needed once
```

Edit `.env` and set:

```bash
# The conformance server will embed this URL in credential offer QR codes and
# redirect_uris so your wallet and browser can reach it.
CONFORMANCE_SERVER_BASE_URL=https://myconformanceserver.share.zrok.io
```

##### Step 4 — Start the conformance server

```bash
cd oid4vc/integration
docker compose -f docker-compose.conformance-only.yml up -d
```

The first run compiles the suite from Maven (~15 min); subsequent starts take
seconds.  Wait until healthy:

```bash
docker compose -f docker-compose.conformance-only.yml ps
```

##### Step 5 — Open the tunnel

```bash
# --insecure tells zrok to accept the server's self-signed TLS certificate
zrok share reserved --insecure myconformanceserver
```

Keep this terminal running for the entire session.

The UI is available at **`https://localhost:8443`** from your desktop, or at
**`https://myconformanceserver.share.zrok.io`** from your phone.

##### Step 6 — Create a wallet test plan

Open the conformance UI and click **Create plan**.  Choose the wallet test plan
(e.g. `oid4vci-1_0-wallet-test-plan`) and configure:

| Field | Value |
|---|---|
| `server.issuer` | `https://myconformanceserver.share.zrok.io` |
| `credential_format` | `sd_jwt_vc`, `mso_mdoc`, `jwt_vc_json`, etc. |

The conformance suite will display a credential offer QR code or deep link.
Scan it with your wallet app — the QR contains the public zrok URL so it is
reachable from the phone.  The suite then verifies each step of the protocol.

> **Keep the `zrok share reserved` terminal running** for the entire session.

##### Teardown

```bash
docker compose -f docker-compose.conformance-only.yml down -v
```

---

#### Testing a wallet SDK presenting credentials (conformance suite acts as verifier)

This is the OID4VP scenario: the conformance suite sends a presentation request
to your wallet; your wallet selects credentials and returns a presentation; the
suite verifies the presentation matches the spec.

**Traffic flow:**

```
 conformance-server  (https://localhost:8443)
     │  generates presentation request
     │  encodes it as a QR / deep link containing the suite's public URL
     ▼
 Mobile wallet (your SDK on a phone / simulator)
     │  scans QR, fetches presentation request from suite
     │  sends VP response back to suite
     ▼
 zrok  (https://myconformanceserver.share.zrok.io)
     ▼
 conformance-server  — verifies the VP matches the spec
```

The suite needs a public tunnel so the wallet can reach the `response_uri`
callback endpoint embedded in the presentation request.  Your wallet SDK does
not need its own tunnel.

Follow the same steps as [Testing a wallet SDK (conformance suite acts as issuer)](#testing-a-wallet-sdk-conformance-suite-acts-as-issuer) — the only difference is the test plan to select in Step 6:

Choose the OID4VP wallet test plan (e.g. `oid4vp-id2-wallet-test-plan`) and configure:

| Field | Value |
|---|---|
| `server.verifier_url` | `https://myconformanceserver.share.zrok.io` |
| `credential_format` | `sd_jwt_vc`, `mso_mdoc`, etc. |

The suite will display a QR code containing the presentation request.  Scan it
with your wallet; it will fetch the request from the suite's public zrok URL,
select the matching credential, and return the VP.

---

#### Testing an issuer or verifier SDK (conformance suite acts as wallet)

Use this when your SDK is the **issuer** or **verifier** being tested.  The
conformance suite acts as the wallet/client and calls your endpoints — so your
SDK needs a public tunnel, and optionally the conformance server does too for
mobile wallet callback flows.

**Traffic flow (issuer test):**

```
 conformance-server (Docker)
     │  acts as wallet — calls /.well-known, /token, /credential
     ▼
 zrok  (https://mysdkissuer.share.zrok.io)
     ▼
 Your issuer SDK  (http://localhost:<port>)
```

##### Step 1 — Install and enable zrok

*(Same as above — skip if already done.)*

```bash
brew install openziti/ziti/zrok   # macOS
zrok enable <your-token>
```

##### Step 2 — Reserve tunnels

```bash
# Naming rules: lowercase alphanumeric only, 4–32 characters.

# Conformance server tunnel (needed for mobile wallet callback flows)
zrok reserve public --unique-name "myconformanceserver" https://localhost:8443

# Your issuer tunnel
zrok reserve public --unique-name "mysdkissuer" http://localhost:<sdk-issuer-port>

# Your verifier tunnel (if testing a verifier)
zrok reserve public --unique-name "mysdkverifier" http://localhost:<sdk-verifier-port>
```

##### Step 3 — Set the URLs in .env

```bash
cp example.env .env   # only needed once
```

```bash
CONFORMANCE_SERVER_BASE_URL=https://myconformanceserver.share.zrok.io
ISSUER_OID4VCI_ENDPOINT=https://mysdkissuer.share.zrok.io
VERIFIER_OID4VP_ENDPOINT=https://mysdkverifier.share.zrok.io
```

##### Step 4 — Start the conformance server

```bash
cd oid4vc/integration
docker compose -f docker-compose.conformance-only.yml up -d
docker compose -f docker-compose.conformance-only.yml ps
```

##### Step 5 — Open the tunnels

```bash
# Terminal A
zrok share reserved --insecure myconformanceserver
# Terminal B
zrok share reserved mysdkissuer
# Terminal C (if testing a verifier)
zrok share reserved mysdkverifier
```

##### Step 6 — Start your SDK and verify

Start your SDK with its base URL set to `https://mysdkissuer.share.zrok.io`.

```bash
curl https://mysdkissuer.share.zrok.io/.well-known/openid-credential-issuer \
  | jq .credential_issuer
# → "https://mysdkissuer.share.zrok.io"
```

##### Step 7 — Create an issuer or verifier test plan

Open **`https://localhost:8443`** and click **Create plan**.

**OID4VCI issuer** (`oid4vci-1_0-issuer-test-plan`):

| Field | Value |
|---|---|
| `server.issuer` | `https://mysdkissuer.share.zrok.io` |
| `resource.credential_configuration_id` | a config ID your issuer supports |
| `client.client_id` | registered client ID or `public` |

**OID4VP verifier** (`oid4vp-1final-verifier-test-plan`):

| Field | Value |
|---|---|
| `server.verifier_url` | `https://mysdkverifier.share.zrok.io` |
| `credential_format` | `sd_jwt_vc` or `iso_mdl` |

> **Keep all tunnels running** for the session.  If any tunnel drops, reconnect
> it and re-run the failing step.

##### Teardown

```bash
docker compose -f docker-compose.conformance-only.yml down -v
```

---

## Manual Testing Against Plugin Services

Interact with the running integration-test stack directly to explore the admin
API, craft custom credential offers, or debug a specific flow.

**Step 1 — Start services**

```bash
./run-tests.sh dev
```

All services start in the background.  Port bindings live in `.env`
(copy `example.env` → `.env` to customise ports; defaults are used if the file does not exist).

**Step 2 — Explore the admin API and create credential configs**

| Service | URL |
|---|---|
| ACA-Py Issuer admin (Swagger) | `http://localhost:18021/api/doc` |
| ACA-Py Issuer OID4VCI metadata | `http://localhost:18022/.well-known/openid-credential-issuer` |
| ACA-Py Verifier admin (Swagger) | `http://localhost:18031/api/doc` |
| ACA-Py Verifier OID4VP | `http://localhost:18032` |
| Credo agent | `http://localhost:13021` |
| Sphereon wrapper | `http://localhost:13010` |

```bash
# Inspect available credential configurations
curl http://localhost:18022/.well-known/openid-credential-issuer | jq .credential_configurations_supported

# Create a pre-authorized offer (replace <id> with a supported_cred_id from the metadata above)
curl -sX POST http://localhost:18021/oid4vci/credential-offer \
  -H 'Content-Type: application/json' \
  -d '{"supported_cred_id": "<id>"}' | jq .

# List OID4VP presentation requests
curl http://localhost:18031/oid4vp/presentations | jq .
```

**Step 3 — Run the integration tests**

```bash
# Run all tests inside the test-river container
docker compose exec test-river uv run pytest tests/ -v

# Filter by credential type
docker compose exec test-river uv run pytest tests/ -m mdoc -v
docker compose exec test-river uv run pytest tests/ -m sdjwt -v
```

**Logs / teardown**

```bash
docker compose logs -f acapy-issuer    # tail issuer logs
./run-tests.sh clean                   # stop + remove volumes
```

---

## Quick Start (automated test run)

```bash
# Build images and run the full test suite in one command
./run-tests.sh

# Or with Docker Compose directly
docker compose up --build --abort-on-container-exit
```

### Specific test categories

```bash
docker compose run --rm test-river uv run pytest tests/ -m "mdoc"   # mso_mdoc only
docker compose run --rm test-river uv run pytest tests/ -m "sdjwt"  # SD-JWT only
```

---

## Test Structure

```
tests/
├── conftest.py          # Shared fixtures (agent clients, helpers)
├── base.py              # Base test class
├── flows/               # End-to-end credential issuance + presentation flows
├── mdoc/                # mso_mdoc-specific tests
├── dcql/                # DCQL query tests
├── revocation/          # Status list / revocation tests
├── wallets/             # Wallet-specific interop tests
├── validation/          # Input validation and error-handling tests
├── helpers/             # Shared test utilities
└── conformance/         # pytest wrappers for conformance suite results
```

---

## Environment Variables

### Test runner

| Variable | Default | Description |
|---|---|---|
| `ACAPY_ISSUER_ADMIN_URL` | `http://acapy-issuer:8021` | ACA-Py issuer admin API |
| `ACAPY_ISSUER_OID4VCI_URL` | `http://acapy-issuer:8022` | ACA-Py OID4VCI endpoint |
| `ACAPY_VERIFIER_ADMIN_URL` | `http://acapy-verifier:8031` | ACA-Py verifier admin API |
| `ACAPY_VERIFIER_OID4VP_URL` | `http://acapy-verifier:8032` | ACA-Py OID4VP endpoint |
| `CREDO_AGENT_URL` | `http://credo-agent:3021` | Credo JSON-RPC wrapper |
| `SPHEREON_WRAPPER_URL` | `http://sphereon-wrapper:3010` | Sphereon JSON-RPC wrapper |
| `REQUIRE_MDOC` | `false` | Fail if mso_mdoc tests are skipped |

### ACA-Py agents

| Variable | Default | Description |
|---|---|---|
| `OID4VCI_ENDPOINT` | (derived) | Public OID4VCI base URL advertised in metadata |
| `OID4VP_ENDPOINT` | (derived) | Public OID4VP base URL advertised in request objects |
| `WALLET_STORAGE_TYPE` | `sqlite` | Wallet backend (`sqlite` or `postgres`) |
| `OID4VC_MDOC_TRUST_STORE_TYPE` | `wallet` | Trust anchor storage (`wallet` or `file`) |
| `LOG_LEVEL` | `DEBUG` | ACA-Py log level |

---

## Test Results

Results are written to `test-results/`:

| File | Description |
|---|---|
| `junit-quick.xml` | JUnit XML from the standard Docker Compose test run |
| `conformance-junit.xml` | JUnit XML from the OIDF conformance suite run |
