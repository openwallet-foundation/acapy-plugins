# OID4VCI conformance findings (running)

Issuer under test: ACA-Py OID4VC plugin (`modular-keycloak` branch) with Keycloak as the
authorization server, via `demo-keycloak`.

**Plan:** OpenID for Verifiable Credential Issuance 1.0 Final: Test an issuer – alpha
tests (`oid4vci-1_0-issuer-test-plan`), plan `kVTR0KuqH9XtY`.

**Run 1 (all 14 modules):** F2 (x5chain) in every issuing module; F5 in modules 12–13.

**Run 2 (after the demo rebuild with the new certificates and the F5 fix):** all modules
pass except module 4 (F3, open); modules 7 and 10 skip (features not supported).

**Variants:** `vci`, `mdoc`, `pre_authorization_code`, `issuer_initiated`, `simple`,
`private_key_jwt`, `dpop`, `unsigned`, `plain` (credential response encryption).

**Setup:** credential configuration `org.iso.18013.5.1.mDL`; Keycloak realm per demo
tenant with suite clients `oidf-conformance-1` / `-2` (`private_key_jwt`, ES256);
static `tx_code` `000000` (offers have no `tx_code`); offers pushed with
`python3 demo-keycloak/conformance_push_offer.py`.

## Status

Run 1: plan `kVTR0KuqH9XtY`. Run 2: plan `NSz4j4CjtVGSr` (same configuration, new demo
endpoints, new IACA trust anchor).

| # | Module | Run 1 | Run 2 | Findings |
|---|---|---|---|---|
| 1 | metadata-test | PASSED | PASSED | F1 fixed before run 1 |
| 2 | metadata-test-signed | PASSED | PASSED | F1 fixed before run 1 |
| 3 | happy-flow | FAILED | PASSED | F2 fixed |
| 4 | happy-flow-additional-requests | FAILED | FAILED | F3 open; F2 fixed |
| 5 | happy-flow-multiple-clients | FAILED | PASSED | F2 fixed |
| 6 | happy-flow-skip-notification | FAILED | PASSED | F2 fixed |
| 7 | batch-issuance | SKIPPED | SKIPPED | F7 (not supported) |
| 8 | fail-invalid-nonce | PASSED | PASSED | |
| 9 | fail-invalid-jwt-proof-signature | PASSED | PASSED | |
| 10 | fail-invalid-key-attestation-signature | SKIPPED | SKIPPED | F6 (not supported) |
| 11 | fail-missing-proof | PASSED | PASSED | |
| 12 | fail-unknown-credential-configuration | FAILED | PASSED | F5 fixed |
| 13 | fail-unknown-credential-identifier | FAILED | PASSED | F5 fixed |
| 14 | fail-on-access-token-in-query | FAILED | PASSED | F2 fixed |

## Findings

| ID | Severity | Area | Summary | Status |
|---|---|---|---|---|
| F1 | Warning | Demo data | `background_image.alt_text` in issuer metadata | Fixed (demo) |
| F2 | Failure + 2 warnings | Demo certificate | Trust anchor in mdoc `x5chain`; IACA/DS profile | Fixed (demo); verified in run 2 |
| F3 | 2 × Failure | Plugin (`/credential`) | Repeat credential requests with the same access token rejected | Open (pre-existing on `main`) |
| F4 | Warning | Deployment (ngrok) | TLS 1.2 cipher outside BCP 195 accepted | Not the plugin |
| F5 | Failure | Plugin (`/credential`) | Non-standard error codes for unknown configuration / identifier | Fixed; verified in run 2 |
| F6 | Skipped | Plugin (not supported) | Key attestation (`key_attestations_required`) | Not supported |
| F7 | Skipped | Plugin (not supported) | Batch issuance (`batch_credential_issuance`) | Not supported (permitted) |

### F1 – Undefined parameter in credential issuer metadata (fixed)

- **Modules:** metadata-test, metadata-test-signed (plan 1).
- **Check:** `CheckForUnexpectedParametersInCredentialIssuerMetadata` (OID4VCI 1.0
  §12.2.3, §12.2.4).
- **Cause:** the demo's mDL configuration had `alt_text` in
  `credential_metadata.display[].background_image`. OID4VCI 1.0 §12.2.4 defines
  `alt_text` for `logo` but only `uri` for `background_image`. The spec's parameter
  lists are non-exhaustive, so this is not a spec violation; the suite warns on any
  parameter the spec does not define. The same warning also listed
  `cryptographic_binding_methods_supported` and `proof_types_supported` as unexpected,
  a side effect of the undefined member.
- **Fix:** removed `alt_text` from `background_image` in `demo/frontend/index.js`
  (`logo.alt_text` is still fine). After the demo restart, both metadata tests pass.

### F2 – Trust anchor included in the mdoc x5chain (fixed)

- **Modules:** happy-flow, happy-flow-additional-requests.
- **Failure:** `ValidateMdocDsCertificateChain`: "Trust anchor certificate must not be
  included in x5c chain" (ISO 18013-5 §9.3.1).
- **Warnings:**
  - `ValidateMdocDsCertificateProfile`: DS validity exceeds 457 days (ISO 18013-5 B.1.4);
  - `ValidateMdocTrustAnchorIacaCertificateProfile`: IACA subject has no CN (B.1.2).
- **Cause:** the demo used one self-signed certificate as both the trust anchor and the
  imported signing certificate.
- **Fix:** `demo/generate_mdoc_certs.py` generates a test IACA root (with CN)
  and a document signer (1 year) issued by it; the demo imports the DS certificate and key
  as the signing key and registers the IACA as the trust anchor. After the demo restart the
  plan's Credential Trust Anchor must be the new IACA.
- **Verified:** run 2 passes the x5chain and certificate profile checks with the new
  certificates.

### F3 – Same access token rejected for further credential requests (open)

- **Module:** happy-flow-additional-requests (2 failures, `EnsureHttpStatusCodeIsAnyOf`,
  OID4VCI 1.0 §8.3; expected 200/202, got 400).
- **Response:** `invalid_credential_request`, "No credential offer available."
- **Sequence:** credential issued (exchange `issued`) → `credential_accepted`
  notification (exchange `accepted`) → two more credential requests with the same access
  token and fresh nonces → rejected, because the credential endpoint only issues from an
  exchange in `created` / `offer` state.
- **Spec:** OID4VCI 1.0 §14.3: "The Credential Endpoint can be accessed multiple times by a
  Wallet using the same Access Token, even for the same Credential."
- **Origin:** pre-existing plugin behaviour; `main` has the same lookup.
- **Proposed fix:** store a hash of the access token on the exchange at first issuance;
  later requests with the same, still valid token re-issue from the `issued` / `accepted`
  exchange (bound to the new proof); other tokens (e.g. after a refresh) still need a new
  offer.
- **Decision:** pending (separate PR proposed).

### F4 – TLS cipher warning (deployment)

- **Module:** happy-flow-additional-requests.
- **Check:** `RequireOnlyBCP195RecommendedCiphersForTLS12` (RFC 9325 §4.2): the issuer
  host accepted `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`.
- **Cause:** TLS is terminated by ngrok, not the plugin. A production deployment's TLS
  terminator should allow only BCP 195 ciphers.

### F5 – Non-standard credential error codes (fixed)

- **Module:** fail-unknown-credential-configuration (module 13,
  fail-unknown-credential-identifier, is expected to fail the same way).
- **Check:** `VCIValidateCredentialErrorResponse` (OID4VCI 1.0 §8.3.1): "Non-standard
  credential error response error code found: invalid_credential_configuration";
  expected `unknown_credential_configuration`.
- **Cause:** `oid4vc/public_routes/credential.py` rejects the request correctly (400) but
  with `invalid_credential_configuration`, and `invalid_credential_identifier` for an
  unknown `credential_identifier`. OID4VCI 1.0 §8.3.1 defines
  `unknown_credential_configuration` and `unknown_credential_identifier`.
- **Origin:** pre-existing; `main` has the same codes.
- **Fix:** `credential.py` now returns `unknown_credential_configuration` /
  `unknown_credential_identifier`; unit tests added for both. Modules 12 and 13 pass in
  run 2.

### F6 – Key attestation not supported (skipped)

- **Module:** fail-invalid-key-attestation-signature (module 10), skipped in both runs: "This
  test requires key attestation. The selected credential configuration uses 'jwt' proof
  type without key_attestations_required."
- Run 2 also has a FAILED instance: an offer was pushed after the test had already finished
  as skipped ("Illegal test state change: FINISHED -> RUNNING"); the rerun skipped cleanly.
  Don't push an offer to this module.
- Revisit when the issuer supports key attestation.

### F7 – Batch issuance not supported (skipped)

- **Module:** batch-issuance (module 7), skipped in both runs: the issuer metadata has no
  `batch_credential_issuance`, which the suite accepts as permitted behaviour.

## Test-suite notes

- happy-flow-multiple-clients needs two offers: after the first client gets its
  credential it waits again ("Pre-authorized codes are single-use, so a new Credential
  Offer for the second client is needed"). Run the offer script a second time.
- Pre-authorized code tests wait for a `tx_code` on `/tx_code` even when the offer has no
  `tx_code` object. A static `tx_code` in the plan avoids the manual step; the issuer
  ignores a `tx_code` for offers without one.
- After a demo restart (new ngrok URLs, and a new tenant and realm on every demo-app
  restart): edit the plan configuration from the "⋯" menu of any test module (Credential
  Issuer URL, Authorization Server URL Override, Credential Trust Anchor if the certificates
  changed), register the suite clients in the new realm, and do one mDL issuance so the
  metadata has the configuration.
