## OID4VC ACA-Py Plugin Demo with Keycloak

The same demo as [`../demo`](../demo/README.md) (JWT, SD-JWT and mdoc
issuance through a UI, status lists, credential refresh), with **Keycloak** as
the OAuth authorization server instead of the reference authorization server.
The reference authorization server and its database are not started.
**Do not use for production deployments.**

You will need ngrok with a valid authentication token (the ngrok config uses
three tunnels, which needs a paid plan).

```
cp .env.example .env    # set NGROK_AUTHTOKEN
docker compose up --build
```

Services:

| Service | What |
|---|---|
| `issuer` | ACA-Py with the OID4VC plugins, including `oid4vc_keycloak` |
| `keycloak` | Keycloak built from [`../keycloak`](../keycloak/README.md) with the OID4VCI pre-authorized code extension |
| `demo-app` | The demo UI. It is shared with `../demo` and built from [`../demo/frontend`](../demo/frontend); `AUTH_SERVER=keycloak` selects Keycloak |
| `ngrok` | Public tunnels for the issuer, the demo UI and Keycloak ([`ngrok.yml`](ngrok.yml)) |
| `webhook-listener` | Echoes the issuer's webhooks |

At startup the demo app:

1. creates a realm `oid4vci-<wallet id>` for its issuer tenant through the
   Keycloak admin API, with the generic holder user, the wallet client(s),
   refresh token rotation, and the extension's refresh client hint in the
   client authentication flow;
2. sets the tenant's authorization server to that realm
   (`PUT /oid4vci/issuer/configuration` with `"type": "keycloak"`).

Wallets get their access token from Keycloak, through its ngrok URL.
Keycloak redeems the pre-authorized code on the issuer's admin API
(`/oid4vci/pre-auth/redeem`), authenticating with a client assertion signed by
the realm key that names the tenant's credential issuer. The wallet also gets
a DPoP-bound refresh token (one year by default, rotated on each use), so
credential refresh works as in `../demo`. The navigation bar shows which
authorization server is in use.

### Settings

In `.env` (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `NGROK_AUTHTOKEN` | — | Your ngrok token |
| `KEYCLOAK_REQUIRE_ATTESTATION` | `false` | Require wallet attestation (ABCA). Off so any wallet works. |
| `KEYCLOAK_WALLET_CLIENT_ID` | — | Your wallet's `client_id`, registered as an attestation-based client |
| `KEYCLOAK_ATTESTER_JWKS` / `KEYCLOAK_ATTESTER_JWKS_URL` | — | Your wallet provider's attester public keys (a one-line JWKS JSON, or a JWKS URL) |
| `KEYCLOAK_REQUIRE_DPOP` | `true` | Require DPoP on the token request. Set `false` for wallets that don't send DPoP. |
| `KEYCLOAK_REFRESH_TOKEN_LIFESPAN` | `31536000` (1 year) | Lifetime of the refresh tokens. They are bound to the wallet's key and rotated on each use. |
| `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | `admin` / `admin` | Keycloak admin account |
| `KEYCLOAK_NGROK_URL` | from ngrok | Static Keycloak URL, if you have one |

To use wallet attestation, set `KEYCLOAK_REQUIRE_ATTESTATION=true`,
`KEYCLOAK_WALLET_CLIENT_ID` and one of the attester settings. The demo app
then adds a trust identity provider for the attester and an
attestation-based client for the wallet. Wallets without attestation are
rejected in that mode.

The Keycloak admin console is at <http://localhost:8180>. The scripted
end-to-end test for the same flow is in
[`../keycloak/e2e`](../keycloak/README.md#end-to-end-test).

`../demo` and `demo-keycloak` use the same ports and image names, so run one
at a time.
