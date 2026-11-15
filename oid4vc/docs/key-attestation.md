# Key Attestation

The Credential Endpoint supports the OpenID4VCI 1.0
[`attestation` proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.3).
A Wallet Provider signs a
[Key Attestation JWT](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.1)
containing one or more holder public keys. The issuer verifies the provider's
signature and attempts to issue a credential instance bound to each key.

This covers `proofs.attestation`, not the `key_attestation` header in `jwt` proofs
(Appendix F.1). Provider trust is configured in the plugin, independently of the
authorization server's Wallet Attestation trust configuration.

## Register a trusted Wallet Provider

Use the tenant's admin API to create a provider with
`POST /oid4vci/wallet-providers`:

```json
{
  "iss": "https://wallet.example.com",
  "jwks_uri": "https://wallet.example.com/.well-known/jwks.json",
  "name": "Example Wallet"
}
```

Alternatively, supply an inline `jwks` object whose `keys` array contains public
JWKs, each with a `kid`. Provider keys must be P-256, P-384, secp256k1 or Ed25519;
inline keys of other types are rejected at registration, and keys of other types
served at `jwks_uri` fail verification. Registration also rejects inline keys whose
`use` is not `sig` or whose `alg` does not match the key type (`ES256`, `ES384`,
`ES256K` or `EdDSA`). Set exactly one of `jwks` or `jwks_uri`; to switch with
`PATCH`, send the new one and set the other to `null`. Registry URLs must use HTTPS.
Providers are tenant-local; inactive providers are not trusted.
The attestation's payload `iss` and header `kid` select the provider and signing key;
keys with a `use` other than `sig` or an `alg` other than the header's are skipped.
Signer trust through `x5c` or `trust_chain` is not supported.

| Method | Admin path | Action |
|---|---|---|
| `POST` | `/oid4vci/wallet-providers` | Create |
| `GET` | `/oid4vci/wallet-providers` | List |
| `GET` | `/oid4vci/wallet-providers/{wallet_provider_id}` | Retrieve |
| `PATCH` | `/oid4vci/wallet-providers/{wallet_provider_id}` | Update supplied fields |
| `DELETE` | `/oid4vci/wallet-providers/{wallet_provider_id}` | Delete |

## Configure the credential's proof types

Include this in the supported credential configuration:

```json
{
  "proof_types_supported": {
    "attestation": {
      "proof_signing_alg_values_supported": ["ES256"],
      "key_attestations_required": {
        "key_storage": ["iso_18045_moderate"]
      }
    }
  }
}
```

`proof_signing_alg_values_supported` may list `ES256`, `ES384`, `ES256K` and
`EdDSA`; other values are rejected.

`key_attestations_required` is optional. When configured, the attestation must
contain at least one accepted value for each listed claim: `key_storage` and/or
`user_authentication`.

This example permits only attestation proofs. Add a `jwt` entry to allow JWT proofs
as well. The configured proof types also apply to the draft-era singular `proof`
parameter, so it cannot bypass an attestation-only configuration.

## Send a credential request

When the Nonce Endpoint is enabled, obtain `c_nonce` from `POST /nonce`. The Wallet
Provider includes that value as the attestation's `nonce`. Send the signed JWT to
`POST /credential` using the access token required by the issuance flow:

```json
{
  "credential_configuration_id": "UniversityDegreeCredential",
  "proofs": {
    "attestation": ["<signed-key-attestation-jwt>"]
  }
}
```

`proofs` must contain one proof type, and `proofs.attestation` must contain exactly
one JWT, even when it attests multiple keys. The issuer checks:

- Header `typ` is `key-attestation+jwt`; `alg` is advertised for this proof type.
- The signature verifies against the active provider selected by `iss` and `kid`.
- Integer `iat` and `exp` are present. Future `iat` and expired `exp` checks allow
  60 seconds of clock skew.
- `attested_keys` is non-empty and contains public P-256, P-384, secp256k1 or
  Ed25519 keys, without private key members or duplicates. Key-agreement keys such
  as X25519 are rejected, because the holder must sign with the bound key. Non-key
  metadata such as `kid` is removed before binding.
- Optional claims are well formed and configured attestation policies are met.
- The nonce is valid for the configured nonce mode.

Requiring `iss` and `exp` is issuer policy: D.1 does not define `iss` and makes `exp`
optional. All attested keys are validated before the nonce is redeemed or issuance
starts; an invalid attestation does not consume the nonce.

## Nonce handling

With `oid4vci.enable_nonce_endpoint=true` (the default), nonces use database-backed,
single-use redemption. The nonce lifetime is 24 hours, shared with the built-in
access token lifetime; there is no separate attestation nonce setting.

When the endpoint is disabled, the attestation nonce is compared with `c_nonce`
from the access token or exchange record instead of using database redemption.
Expired database nonces are rejected on redemption; automatic cleanup of expired
records is not implemented.

## Multiple attested keys

Without `batch_credential_issuance`, an attestation may attest one key. To accept
more, set the tenant's batch setting through `PUT /oid4vci/issuer/configuration`;
issuer metadata publishes it, so wallets know the limit:

```json
{
  "batch_credential_issuance": {
    "batch_size": 10
  }
}
```

`batch_size` must be an integer of 2 or more; other values are rejected. This is
local policy: the plugin reuses `batch_size` to limit the inner `attested_keys`
array, while the specification's
[batch metadata](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4)
describes proof array size. Oversized attestations receive HTTP 400
`invalid_credential_request` after signature verification, before per-key validation,
nonce redemption, status allocation or signing. Keys are not silently truncated.

For requests within the limit, the issuer redeems the nonce once and attempts one
credential per key. Successful instances are returned in `credentials`; individual
signing failures do not discard other successes. If none succeed, the endpoint
returns `invalid_credential_request` and marks a multi-key exchange failed.

All instances share one exchange ID and, when configured, one `notification_id`.
Configured status entries are shared per status definition: revoking a shared
entry revokes every instance, but also makes those instances linkable through
their status reference. Status allocation is attempted once, just before signing;
it is not retried per key or rolled back if all signing attempts fail. `mso_mdoc`
status behaves as in single-key issuance: a failed allocation leaves the instances
without status, and the entry cannot be updated through the status_list admin API.

| Format | Holder binding | Batch timing |
|---|---|---|
| `jwt_vc_json` | Subject `did:jwk` derived from the normalized public JWK | Shared issuance time; configured expiry |
| `dc+sd-jwt` | Public JWK and its `did:jwk` key identifier in `cnf` | Shared issuance time and expiry |
| `mso_mdoc` | EC public key in the MSO DeviceKey | Native 30-day validity, calculated per signing call |

## Remote keys and current limitations

Remote JWKS use a five-minute cache with a 60-second minimum refresh interval for
an unknown `kid`, measured from the last successful fetch. Failed refreshes reject
the request rather than fall back to stale keys. The cache does not coalesce
concurrent fetches, back off after failed fetches, restrict redirects or apply a
fetch-specific timeout; HTTPS is checked when the provider URL is registered.

Publishing `batch_size` also tells wallets that `proofs` may carry more than one
proof, but `proofs.jwt` accepts exactly one JWT.

## Errors

| Error | Cause |
|---|---|
| `invalid_proof` | Unsupported proof type; malformed attestation; untrusted signer; bad signature; expired or invalid claims; private, unsupported, invalid or duplicate keys; unmet policy; cache-level JWKS rejection, including HTTP errors or missing keys |
| `invalid_nonce` | Nonce unknown, expired, already used, or mismatched in token/exchange nonce mode |
| `invalid_credential_request` | More than one proof type; attested-key limit exceeded; no credential instance could be issued |
| `credential_request_denied` | Wallet Provider JWKS transport, timeout or JSON-decoding failure |