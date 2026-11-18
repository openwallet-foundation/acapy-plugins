# X.509 Certificates

## Description

Standalone ACA-Py plugin that creates CSRs and stores X.509 certificates for
wallet keys, and stores trust anchors used to verify certificate chains.
Supported ACA-Py version: **1.7.0**; Python **3.13+**.

The plugin has no OID4VC dependency. It uses the wallet's signing interface for
CSRs and self-signed certificates without exporting private keys.

## Installation

From the acapy-plugins repository root:

```sh
python -m pip install './x509_certs[aca-py]'
```

Omit the `aca-py` extra if ACA-Py is already installed. Add
`--plugin x509_certs` to your ACA-Py startup arguments to load the plugin
and register its admin routes. Installing the distribution does not load it.

## Configuration

| Setting | Default | Effect |
|---|---|---|
| `x509.allow_self_signed` | `false` | Enables `POST /x509/certificates/self-signed`; for development only |

Set it with a startup option:

```sh
--plugin-config-value x509.allow_self_signed=true
```

or in a file passed with `--plugin-config`:

```yaml
x509:
  allow_self_signed: true
```

## API

All routes use ACA-Py's tenant authentication. Certificate and trust-anchor
records are stored in the calling tenant's wallet.

| Method | Path | Purpose |
|---|---|---|
| POST | `/x509/csr` | Request a PEM CSR signed by a P-256 wallet key |
| POST | `/x509/certificates` | Import a leaf-first PEM chain whose leaf matches a wallet key |
| GET | `/x509/certificates` | List certificates; filter by `multikey`, `kid`, `purpose`, `subject` or `valid_at` |
| GET | `/x509/certificates/{cert_id}` | Get a stored certificate chain and its parsed fields |
| DELETE | `/x509/certificates/{cert_id}` | Delete a certificate |
| POST | `/x509/certificates/self-signed` | Create a self-signed certificate for development |
| POST | `/x509/trust-anchors` | Import one PEM CA certificate with a purpose |
| GET | `/x509/trust-anchors` | List anchors; filter by `purpose` or `subject` |
| GET | `/x509/trust-anchors/{anchor_id}` | Get an anchor |
| DELETE | `/x509/trust-anchors/{anchor_id}` | Delete an anchor |
| POST | `/x509/verify` | Check a leaf-first chain against anchors for its certificate purpose |

Certificate imports support P-256 and Ed25519 wallet keys. CSR and self-signed
creation support P-256 keys only.

### Certificate purposes

| Certificate purpose | Matching trust-anchor purpose |
|---|---|
| `mdoc_ds` | `iaca` |
| `sd_jwt_vc_issuer` | `sd_jwt_vc_ca` |

`POST /x509/verify` takes either `chain` (PEM) or `x5c` (standard base64 DER),
a certificate `purpose`, and an optional `at` timestamp. It checks signatures,
validity and issuer CA flags against anchors with the matching purpose.
It is not a general-purpose PKIX policy or revocation validator.

### Example requests

Create a wallet key with `POST /wallet/keys` and `{"alg": "p256"}`. Use the
returned `multikey` in a CSR request:

```json
{
  "multikey": "<wallet multikey>",
  "subject": {"common_name": "Example Issuer"},
  "dns_names": ["issuer.example.com"]
}
```

Have a CA sign the CSR, then import the chain with `POST /x509/certificates`:

```json
{
  "chain": "<leaf-first PEM certificate chain>",
  "purpose": "sd_jwt_vc_issuer"
}
```

## Python API

Consumers can import certificate selection, chain formatting, records and
`X509Error` from `x509_certs`. `select_certificate` selects a certificate
for a multikey and purpose whose validity covers the requested expiry,
preferring the earliest expiry and then the earliest start date.

## Development

From this directory:

```sh
poetry install --with integration --all-extras
poetry run pytest
poetry run ruff check .
poetry run ruff format --check .
poetry check --lock
poetry build
```

The project follows `plugin_globals`, including shared Poetry settings,
`.devcontainer`, `.vscode`, `docker` and `integration` scaffolding. The unit
suite loads `x509_certs` through ACA-Py's registry and calls its routes over HTTP.

Run the [Docker integration suite](./integration/README.md) to exercise wallet
keys, CSR generation, certificate/anchor CRUD and verification through one
agent's admin API. CI runs both the unit and Docker integration suites.

The sample Docker configurations are for development; replace their example
API and wallet keys before deploying.
