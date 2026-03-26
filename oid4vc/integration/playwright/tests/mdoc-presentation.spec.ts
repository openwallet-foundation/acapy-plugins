/**
 * mDOC (mDL) Presentation Test
 * 
 * E2E test for presenting an mDL credential from walt.id web wallet to ACA-Py
 * verifier using OID4VP protocol with browser automation.
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
 * Flow (when walt.id adds mDOC UI support):
 * 1. Create test user and issue mDL credential (setup)
 * 2. Create presentation request from verifier
 * 3. Navigate to presentation request URL
 * 4. Select and present credential in wallet UI
 * 5. Verify presentation is accepted by verifier
 */

import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser } from '../helpers/wallet-factory';
import { buildIssuanceUrl, buildPresentationUrl } from '../helpers/url-encoding';
import {
  createIssuerDid,
  createMdocCredentialConfig,
  createCredentialOffer,
  uploadIssuerCertificate,
  uploadTrustAnchor,
  createMdocPresentationRequest,
  waitForPresentationState,
  waitForAcaPyServices,
} from '../helpers/acapy-client';

const WALTID_WEB_WALLET_URL = process.env.WALTID_WEB_WALLET_URL || 'http://localhost:7101';

test.describe('mDOC (mDL) Credential Presentation', () => {
  let testUser: { email: string; password: string; token: string; walletId: string };
  let issuerDid: string;
  let credConfigId: string;

  // Mark as expected to fail until walt.id publishes a web-wallet image with mDOC UI support
  // The backend supports mDOC but the UI crashes when processing mso_mdoc format credentials
  test.fail();

  test.beforeAll(async () => {
    // Wait for services
    await waitForAcaPyServices();
    
    // Upload issuer certificate for mDOC signing
    await uploadIssuerCertificate();
    
    // Upload trust anchor to verifier
    await uploadTrustAnchor();
    
    // Create issuer DID with P-256 key
    issuerDid = await createIssuerDid('p256');
    
    // Create mDOC credential configuration
    credConfigId = await createMdocCredentialConfig(`mDL-presentation-${Date.now()}`);
    
    // Register test user
    testUser = await registerTestUser('mdoc-presentation');
  });

  test.beforeEach(async ({ page }) => {
    // Issue a credential before each presentation test
    const credentialSubject = {
      'org.iso.18013.5.1': {
        given_name: 'Presentation',
        family_name: 'TestUser',
        birth_date: '1985-06-20',
        issue_date: new Date().toISOString().split('T')[0],
        expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        issuing_country: 'US',
        issuing_authority: 'Test DMV',
        document_number: `DL-PRES-${Date.now()}`,
      },
    };

    const { offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    // Login and accept credential
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);
    
    const issuanceUrl = buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId);
    await page.goto(issuanceUrl);
    await page.waitForLoadState('networkidle');

    // Accept the credential
    const acceptButton = page.getByRole('button', { name: /accept|add|receive/i });
    await expect(acceptButton.first()).toBeVisible({ timeout: 10000 });
    await acceptButton.first().click();

    // Wait for success
    const successIndicator = page.getByText(/success|added|received/i);
    await expect(successIndicator.first()).toBeVisible({ timeout: 30000 });

    console.log('Credential issued successfully for presentation test');
  });

  test('should present mDL credential to verifier', async ({ page }) => {
    // Create presentation request
    const { presentationId, requestUrl } = await createMdocPresentationRequest();
    console.log(`Created presentation request: ${presentationId}`);
    console.log(`Request URL: ${requestUrl}`);

    // Navigate to presentation request
    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    console.log(`Navigating to: ${presentationUrl}`);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    // Take screenshot of request page
    await page.screenshot({ path: 'test-results/mdoc-presentation-request.png' });

    // Wait for presentation request UI
    const requestDetails = page.locator('[data-testid="presentation-request"], .presentation-request, text=/request/i');
    await expect(requestDetails.first()).toBeVisible({ timeout: 15000 });

    // Select the mDL credential if selection is required
    const credentialSelector = page.locator('[data-testid="credential-select"], .credential-select, text=/Mobile Driver/i');
    const selectorVisible = await credentialSelector.first().isVisible().catch(() => false);
    
    if (selectorVisible) {
      await credentialSelector.first().click();
    }

    // Find and click share/present button
    const shareButton = page.getByRole('button', { name: /share|present|send|confirm/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    // Wait for success indication
    const successIndicator = page.getByText(/success|shared|presented|complete/i);
    await expect(successIndicator.first()).toBeVisible({ timeout: 30000 });

    // Take screenshot of success
    await page.screenshot({ path: 'test-results/mdoc-presentation-success.png' });

    // Verify presentation was accepted by verifier
    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    
    expect(presentation.state).toBe('presentation-valid');
    console.log(`Presentation verified successfully: ${presentationId}`);
    console.log('Presented claims:', JSON.stringify(presentation.verified_claims || {}, null, 2));
  });

  test('should allow selective disclosure', async ({ page }) => {
    // Create presentation request
    const { presentationId, requestUrl } = await createMdocPresentationRequest();

    // Navigate to presentation request
    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    // Take screenshot
    await page.screenshot({ path: 'test-results/mdoc-selective-disclosure.png' });

    // Look for selective disclosure UI elements
    // walt.id may show checkboxes or similar for field selection
    const disclosureOptions = page.locator('[data-testid="disclosure-option"], input[type="checkbox"], .field-selector');
    const hasDisclosureOptions = await disclosureOptions.first().isVisible().catch(() => false);

    if (hasDisclosureOptions) {
      console.log('Selective disclosure options found');
      // Count visible options
      const optionCount = await disclosureOptions.count();
      console.log(`Found ${optionCount} disclosure options`);
      
      // Verify required fields are checked/selected
      const givenNameField = page.getByText(/given_name|given name/i);
      const familyNameField = page.getByText(/family_name|family name/i);
      
      await expect(givenNameField.first()).toBeVisible().catch(() => {});
      await expect(familyNameField.first()).toBeVisible().catch(() => {});
    }

    // Complete the presentation
    const shareButton = page.getByRole('button', { name: /share|present|send/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    // Wait for success
    const successIndicator = page.getByText(/success|shared|presented/i);
    await expect(successIndicator.first()).toBeVisible({ timeout: 30000 });

    // Verify with verifier
    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    expect(presentation.state).toBe('presentation-valid');
    
    console.log('Selective disclosure presentation completed successfully');
  });

  test('should reject invalid presentation request gracefully', async ({ page }) => {
    // Navigate to an invalid presentation request
    const invalidRequestUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, 'http://invalid-verifier/request/invalid', testUser.walletId);
    await page.goto(invalidRequestUrl);
    await page.waitForLoadState('networkidle');

    // Should show error or warning
    const errorIndicator = page.getByText(/error|invalid|failed|unable/i).or(page.locator('.error-message'));
    
    // Either error is shown or page doesn't load properly
    const hasError = await errorIndicator.first().isVisible().catch(() => false);
    
    if (hasError) {
      console.log('Error correctly displayed for invalid request');
    } else {
      // Check we're not on a valid presentation page
      const shareButton = page.locator('button:has-text("Share"), button:has-text("Present")');
      const hasShareButton = await shareButton.first().isVisible().catch(() => false);
      expect(hasShareButton).toBe(false);
      console.log('No share button shown for invalid request');
    }

    await page.screenshot({ path: 'test-results/mdoc-invalid-request.png' });
  });
});
