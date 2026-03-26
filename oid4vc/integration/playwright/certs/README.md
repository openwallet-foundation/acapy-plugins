# Test Certificates for Walt.id mDOC Testing

This directory contains pre-generated ECDSA P-256 certificates for mDOC (mDL) testing with the walt.id web wallet.

## Files

| File | Purpose |
|------|---------|
| `root-ca.key` | Root CA private key (keep secure) |
| `root-ca.pem` | Root CA certificate - trust anchor for verification |
| `issuer.key` | Issuer private key - used by ACA-Py for signing mDOCs |
| `issuer.pem` | Issuer certificate - signed by Root CA |
| `issuer-chain.pem` | Full certificate chain (issuer + root) |
| `x509.conf` | walt.id wallet trust configuration file |
| `generate-certs.sh` | Script to regenerate certificates |

## Certificate Details

- **Algorithm**: ECDSA with P-256 curve (prime256v1)
- **Hash**: SHA-256
- **Validity**: 10 years from generation date
- **Generated**: December 2025
- **Expires**: December 2035

## Usage

### ACA-Py Issuer
Load `issuer.key` and `issuer-chain.pem` into ACA-Py for mDOC signing.

### ACA-Py Verifier
Upload `root-ca.pem` as a trust anchor via the `/oid4vp/trust-anchor` API.

### Walt.id Wallet
Mount `x509.conf` into the wallet-api container at `/waltid-wallet-api/config/x509.conf`.

## Regenerating Certificates

If certificates expire or need to be regenerated:

```bash
cd playwright/certs
./generate-certs.sh
```

Then commit the new certificates to the repository.

## Security Note

These certificates are **for testing only**. The private keys are committed to the repository intentionally to enable reproducible testing. Never use these certificates in production.
