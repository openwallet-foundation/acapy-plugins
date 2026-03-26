/**
 * mDOC (mDL) Issuance Test
 * 
 * E2E test for issuing an mDL credential from ACA-Py to walt.id web wallet
 * using OID4VCI protocol with browser automation.
 * 
 * ⚠️ EXPECTED TO FAIL: walt.id web wallet UI does not currently support mDOC credentials.
 * 
 * The walt.id waltid-web-wallet:latest Docker image (last updated Aug 2024) has a bug
 * in its issuance.ts composable that only handles `types`, `credential_definition.type`,
 * or `vct` fields. The mso_mdoc format uses `doctype` instead, causing:
 * "TypeError: Cannot read properties of undefined (reading 'length')"
 * 
 * walt.id has mDOC support in their backend libraries (waltid-mdoc-credentials) and
 * is working on adding UI support. Once a new web-wallet image is published with
 * mDOC UI support, these tests should pass.
 * 
 * Tracking: https://github.com/walt-id/waltid-identity
 * 
 * For mDOC testing without the web UI, use:
 * - Python tests in tests/test_oid4vc_mdoc_compliance.py (uses Credo agent)
 * - Direct API testing with wallet-api endpoints
 * 
 * Flow (when walt.id adds mDOC UI support):
 * 1. Create test user in walt.id wallet
 * 2. Configure mDOC credential in ACA-Py issuer
 * 3. Create credential offer
 * 4. Navigate to offer URL in browser
 * 5. Accept credential in wallet UI
 * 6. Verify credential appears in wallet
 */

import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser, listWalletCredentials } from '../helpers/wallet-factory';
import { buildIssuanceUrl } from '../helpers/url-encoding';
import {
  createIssuerDid,
  createMdocCredentialConfig,
  createCredentialOffer,
  uploadIssuerCertificate,
  waitForAcaPyServices,
} from '../helpers/acapy-client';

const WALTID_WEB_WALLET_URL = process.env.WALTID_WEB_WALLET_URL || 'http://localhost:7101';

test.describe('mDOC (mDL) Credential Issuance', () => {
  let testUser: { email: string; password: string; token: string; walletId: string };
  let issuerDid: string;
  let credConfigId: string;

  test.beforeAll(async () => {
    // Wait for services
    await waitForAcaPyServices();
    
    // Upload issuer certificate for mDOC signing
    await uploadIssuerCertificate();
    
    // Create issuer DID with P-256 key (required for mDOC)
    issuerDid = await createIssuerDid('p256');
    
    // Create mDOC credential configuration
    credConfigId = await createMdocCredentialConfig();
    
    // Register test user
    testUser = await registerTestUser('mdoc-issuance');
  });

  // Mark as expected to fail until walt.id publishes a web-wallet image with mDOC UI support
  // The backend supports mDOC but the UI crashes when processing mso_mdoc format credentials
  test.fail();

  test('should issue mDL credential to wallet', async ({ page }) => {
    // Capture console messages for debugging
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      consoleLogs.push(`[PAGE ERROR] ${err.message}`);
    });

    // Create credential offer
    const credentialSubject = {
      'org.iso.18013.5.1': {
        given_name: 'Test',
        family_name: 'User',
        birth_date: '1990-01-15',
        issue_date: new Date().toISOString().split('T')[0],
        expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        issuing_country: 'US',
        issuing_authority: 'Test DMV',
        document_number: 'DL-TEST-12345',
        portrait: 'iVBORw0KGgoAAAANSUhEUg==', // Minimal base64 placeholder
        driving_privileges: [
          { vehicle_category_code: 'C', issue_date: '2020-01-01', expiry_date: '2030-01-01' },
        ],
      },
    };

    const { exchangeId, offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    console.log(`Created credential offer: ${exchangeId}`);
    console.log(`Offer URL: ${offerUrl}`);

    // Login to wallet
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to credential offer
    const issuanceUrl = buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId);
    console.log(`Navigating to: ${issuanceUrl}`);
    await page.goto(issuanceUrl);

    // Wait for the offer page to load
    await page.waitForLoadState('networkidle');
    
    // Screenshot before hydration check
    await page.screenshot({ path: 'test-results/mdoc-before-hydration.png' });
    
    // Log collected network calls
    console.log('Collected network logs:');
    consoleLogs.filter(l => l.includes('NETWORK') || l.includes('RESPONSE')).forEach(l => console.log(l));

    // Wait for Vue to hydrate (same pattern as debug-ui.spec.ts)
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
    } catch (error) {
      // On failure, log what we have
      console.log('HYDRATION FAILED - Console logs:');
      consoleLogs.forEach(l => console.log(l));
      
      // Get page HTML for debugging
      const html = await page.content();
      console.log('Page HTML (first 2000 chars):', html.substring(0, 2000));
      throw error;
    }

    // Take screenshot of offer page
    await page.screenshot({ path: 'test-results/mdoc-issuance-offer.png' });

    // Find and click accept button - use the same pattern as working tests
    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 10000 });
    await acceptButton.click();

    // Wait for redirect to wallet dashboard
    await page.waitForURL(/\/wallet\/[^/]+(?:$|\?)/, { timeout: 30000 });

    // Take screenshot of success
    await page.screenshot({ path: 'test-results/mdoc-issuance-success.png' });

    // Navigate to credentials list to verify - use correct URL
    await page.goto(`${WALTID_WEB_WALLET_URL}/wallet/${testUser.walletId}`);
    await page.waitForLoadState('networkidle');

    // Wait for the dashboard to load
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0;
    }, { timeout: 10000 });

    // Take final screenshot
    await page.screenshot({ path: 'test-results/mdoc-issuance-final.png' });

    // Also verify via API
    const credentials = await listWalletCredentials(testUser.token, testUser.walletId);
    expect(credentials.length).toBeGreaterThanOrEqual(1);
    
    console.log(`Successfully issued mDL credential. Wallet now has ${credentials.length} credential(s).`);
  });

  test('should display credential details correctly', async ({ page }) => {
    // Login to wallet
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to credentials
    await page.goto(`${WALTID_WEB_WALLET_URL}/wallet/${testUser.walletId}`);
    await page.waitForLoadState('networkidle');

    // Wait for the dashboard to load  
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0;
    }, { timeout: 10000 });

    // Take screenshot to show credentials
    await page.screenshot({ path: 'test-results/mdoc-credential-details.png' });

    // Verify via API
    const credentials = await listWalletCredentials(testUser.token, testUser.walletId);
    console.log(`Wallet has ${credentials.length} credential(s)`);
    expect(credentials.length).toBeGreaterThanOrEqual(1);
  });
});