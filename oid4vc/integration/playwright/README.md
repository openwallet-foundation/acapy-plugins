# Playwright E2E Tests for OID4VC

Browser automation tests for OID4VCI (credential issuance) and OID4VP (credential presentation) 
using the walt.id web wallet as a real-world holder application.

## Overview

These tests validate the complete OID4VC flows by:
1. Running ACA-Py as issuer and verifier
2. Running walt.id web wallet as the holder
3. Using Playwright to automate the browser-based wallet UI
4. Verifying credentials are properly issued, stored, and presented

## Credential Formats Tested

| Format | Issuance | Presentation | Selective Disclosure |
|--------|----------|--------------|---------------------|
| mDOC (mDL) | ✅ | ✅ | ✅ |
| SD-JWT | ✅ | ✅ | ✅ |
| JWT-VC | ✅ | ✅ | N/A |

## Prerequisites

- Docker and Docker Compose
- Node.js 18+
- npm or yarn

## Quick Start

```bash
# Run all tests
./run-playwright-tests.sh

# Run only mDOC tests
./run-playwright-tests.sh --mdoc-only

# Run with visible browser (headed mode)
./run-playwright-tests.sh --headed

# Open Playwright UI for interactive debugging
./run-playwright-tests.sh --ui
```

## Project Structure

```
playwright/
├── certs/                    # X.509 certificates for mDOC
│   ├── generate-certs.sh     # Certificate generation script
│   ├── root-ca.pem           # Root CA certificate
│   ├── issuer.pem            # Issuer certificate
│   ├── issuer-chain.pem      # Full certificate chain
│   └── x509.conf             # walt.id trust anchor config
├── helpers/                   # Test utility modules
│   ├── acapy-client.ts       # ACA-Py admin API wrapper
│   ├── url-encoding.ts       # Base64url encoding for URLs
│   └── wallet-factory.ts     # User/wallet creation helpers
├── tests/                     # Test specifications
│   ├── mdoc-issuance.spec.ts
│   ├── mdoc-presentation.spec.ts
│   ├── sdjwt-flow.spec.ts
│   └── jwtvc-flow.spec.ts
├── test-results/              # Screenshots, videos, traces
├── playwright.config.ts       # Playwright configuration
├── package.json
├── tsconfig.json
└── run-playwright-tests.sh    # Main entry point
```

## Services

The tests use Docker Compose with the `waltid` profile:

| Service | Port | Description |
|---------|------|-------------|
| acapy-issuer | 8021 (admin), 8022 (OID4VCI) | ACA-Py issuer agent |
| acapy-verifier | 8031 (admin), 8032 (OID4VP) | ACA-Py verifier agent |
| waltid-wallet-api | 7001 | walt.id wallet backend API |
| waltid-web-wallet | 7101 | walt.id web wallet frontend |
| waltid-postgres | 5433 | PostgreSQL for walt.id |

## Configuration

### Environment Variables

```bash
# ACA-Py URLs
ACAPY_ISSUER_ADMIN_URL=http://localhost:8021
ACAPY_VERIFIER_ADMIN_URL=http://localhost:8031

# walt.id URLs
WALTID_API_URL=http://localhost:7001
WALTID_WEB_WALLET_URL=http://localhost:7101
```

### Playwright Config

Edit `playwright.config.ts` to modify:
- Number of parallel workers (default: 4)
- Video recording settings
- Browser selection
- Timeouts

## Test Flow

### mDOC Issuance Test

1. Create test user in walt.id wallet
2. Upload X.509 issuer certificate to ACA-Py
3. Create mDOC credential configuration
4. Generate credential offer URL
5. Navigate browser to offer URL
6. Accept credential in wallet UI
7. Verify credential appears in wallet

### mDOC Presentation Test

1. Issue credential to wallet (setup)
2. Create presentation request from verifier
3. Navigate to presentation URL
4. Select and share credential
5. Verify presentation state at verifier

## Certificate Management

The mDOC (mDL) tests require X.509 certificates for document signing and verification:

```bash
# Regenerate certificates
cd certs
./generate-certs.sh

# Certificates are valid for 10 years
```

### Certificate Chain

```
Root CA (self-signed)
└── Issuer Certificate (signed by Root CA)
```

The root CA is configured as a trust anchor in both:
- ACA-Py verifier (via API upload)
- walt.id wallet (via `x509.conf` mount)

## Debugging

### View Test Report

```bash
npx playwright show-report
```

### Run Specific Test

```bash
npx playwright test mdoc-issuance --headed
```

### Debug Mode

```bash
# Step through test with Playwright Inspector
npx playwright test --debug

# Or use the UI mode
npx playwright test --ui
```

### View Container Logs

```bash
# walt.id wallet API logs
docker compose logs waltid-wallet-api -f

# ACA-Py issuer logs
docker compose logs issuer -f
```

## Troubleshooting

### Tests fail with "Service not ready"

Ensure all services are running:
```bash
docker compose --profile waltid ps
```

Wait for health checks:
```bash
curl http://localhost:8021/status/ready
curl http://localhost:7001/health
```

### mDOC tests fail with certificate errors

Regenerate certificates and restart services:
```bash
cd certs
./generate-certs.sh
cd ..
docker compose --profile waltid restart waltid-wallet-api
```

### Browser automation fails to find elements

The walt.id wallet UI may have changed. Update selectors in test files:
```typescript
// Example: Update button selectors
const acceptButton = page.locator('button:has-text("Accept"), button:has-text("Add")');
```

Use Playwright Inspector to find correct selectors:
```bash
npx playwright test --debug
```

## CI/CD Integration

The tests can run in CI using the Docker-based approach:

```yaml
# GitHub Actions example
- name: Run Playwright tests
  run: |
    cd oid4vc/integration/playwright
    ./run-playwright-tests.sh

- name: Upload test artifacts
  uses: actions/upload-artifact@v3
  with:
    name: playwright-report
    path: oid4vc/integration/playwright/playwright-report/
```

## Adding New Tests

1. Create test file in `tests/` directory
2. Import helpers from `helpers/`
3. Use `registerTestUser()` for unique test users
4. Use `loginViaBrowser()` for wallet authentication
5. Use `buildIssuanceUrl()`/`buildPresentationUrl()` for navigation

Example:
```typescript
import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser } from '../helpers/wallet-factory';
import { buildIssuanceUrl } from '../helpers/url-encoding';
import { createCredentialOffer } from '../helpers/acapy-client';

test('my new credential test', async ({ page }) => {
  const user = await registerTestUser('my-test');
  await loginViaBrowser(page, user.email, user.password);
  
  const { offerUrl } = await createCredentialOffer(...);
  await page.goto(buildIssuanceUrl(WALLET_URL, offerUrl));
  
  // ... continue test
});
```

## License

See parent project LICENSE.
