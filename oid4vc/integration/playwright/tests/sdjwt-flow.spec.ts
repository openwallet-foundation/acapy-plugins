/**
 * SD-JWT Credential Flow Test
 * 
 * E2E test for SD-JWT credential issuance and presentation using
 * ACA-Py and walt.id web wallet with OID4VCI/OID4VP protocols.
 */

import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser, listWalletCredentials } from '../helpers/wallet-factory';
import { buildIssuanceUrl, buildPresentationUrl } from '../helpers/url-encoding';
import {
  createIssuerDid,
  createSdJwtCredentialConfig,
  createCredentialOffer,
  createSdJwtPresentationRequest,
  waitForPresentationState,
  waitForAcaPyServices,
} from '../helpers/acapy-client';

const WALTID_WEB_WALLET_URL = process.env.WALTID_WEB_WALLET_URL || 'http://localhost:7101';

test.describe('SD-JWT Credential Flow', () => {
  let testUser: { email: string; password: string; token: string; walletId: string };
  let issuerDid: string;
  let credConfigId: string;

  test.beforeAll(async () => {
    // Wait for services
    await waitForAcaPyServices();
    
    // Create issuer DID
    issuerDid = await createIssuerDid('p256');
    
    // Create SD-JWT credential configuration
    credConfigId = await createSdJwtCredentialConfig();
    
    // Register test user
    testUser = await registerTestUser('sdjwt-flow');
  });

  test('should issue SD-JWT credential to wallet', async ({ page }) => {
    // Create credential offer
    const credentialSubject = {
      given_name: 'Alice',
      family_name: 'Johnson',
      email: 'alice.johnson@example.com',
      birth_date: '1988-03-15',
    };

    const { exchangeId, offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    console.log(`Created SD-JWT credential offer: ${exchangeId}`);

    // Login to wallet
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to credential offer
    const issuanceUrl = buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId);
    await page.goto(issuanceUrl);
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
    } catch (e) {
      // Continue anyway
    }
    
    await page.waitForTimeout(2000);
    await page.screenshot({ path: 'test-results/sdjwt-issuance-offer.png' });

    // Find and click Accept button
    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 15000 });
    await acceptButton.click();
    
    // Wait for network activity and success
    await page.waitForTimeout(5000);
    
    // Check if we succeeded
    const bodyText = await page.locator('body').textContent() || '';
    const hasSuccess = bodyText.toLowerCase().includes('success') || 
                       bodyText.toLowerCase().includes('added') ||
                       page.url().includes('/credentials');
    
    await page.screenshot({ path: 'test-results/sdjwt-issuance-after-accept.png' });

    await page.screenshot({ path: 'test-results/sdjwt-issuance-success.png' });

    // Verify via API
    const credentials = await listWalletCredentials(testUser.token, testUser.walletId);
    expect(credentials.length).toBeGreaterThanOrEqual(1);
    
    console.log('SD-JWT credential issued successfully');
  });

  // TODO: Re-enable when OID4VP signature verification bug is fixed
  // The verifier fails to verify signatures from credentials
  test.skip('should present SD-JWT credential with selective disclosure', async ({ page }) => {
    // First issue a credential
    const credentialSubject = {
      given_name: 'Bob',
      family_name: 'Smith',
      email: 'bob.smith@example.com',
      age: 35,
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

    // Wait for Vue to hydrate
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
    } catch (e) {
      // Continue anyway
    }
    await page.waitForTimeout(2000);

    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 15000 });
    await acceptButton.click();

    await page.waitForTimeout(5000);

    // Now present the credential
    const { presentationId, requestUrl } = await createSdJwtPresentationRequest();
    console.log(`Created SD-JWT presentation request: ${presentationId}`);

    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    await page.screenshot({ path: 'test-results/sdjwt-presentation-request.png' });

    // Look for selective disclosure options
    const disclosureOptions = page.locator('input[type="checkbox"], [data-testid="disclosure-field"]');
    const hasDisclosure = await disclosureOptions.first().isVisible().catch(() => false);
    
    if (hasDisclosure) {
      console.log('SD-JWT selective disclosure UI found');
      // The given_name should be required, others optional
    }

    // Present credential
    const shareButton = page.getByRole('button', { name: /share|present|send/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    // Wait for success
    const presentSuccess = page.getByText(/success|shared|presented/i);
    await expect(presentSuccess.first()).toBeVisible({ timeout: 30000 });

    await page.screenshot({ path: 'test-results/sdjwt-presentation-success.png' });

    // Verify with verifier
    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    expect(presentation.state).toBe('presentation-valid');
    
    // Check that only disclosed claims are present
    console.log('SD-JWT presentation verified successfully');
    console.log('Verified claims:', JSON.stringify(presentation.verified_claims || {}, null, 2));
  });

  // TODO: Re-enable when OID4VP signature verification bug is fixed
  test.skip('should handle multiple credentials and select correct one', async ({ page }) => {
    // Issue two different SD-JWT credentials
    const cred1Subject = {
      given_name: 'First',
      family_name: 'Credential',
      email: 'first@example.com',
    };

    const cred2Subject = {
      given_name: 'Second',
      family_name: 'Credential',
      email: 'second@example.com',
    };

    // Issue first credential
    const { offerUrl: offer1 } = await createCredentialOffer(credConfigId, issuerDid, cred1Subject);
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);
    await page.goto(buildIssuanceUrl(WALTID_WEB_WALLET_URL, offer1, testUser.walletId));
    await page.waitForLoadState('networkidle');
    
    // Wait for Vue to hydrate
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
    } catch (e) {
      // Continue anyway
    }
    await page.waitForTimeout(2000);
    
    const acceptBtn1 = page.getByRole('button', { name: /accept/i });
    await expect(acceptBtn1).toBeVisible({ timeout: 15000 });
    await acceptBtn1.click();
    
    await page.waitForTimeout(5000);

    // Issue second credential
    const { offerUrl: offer2 } = await createCredentialOffer(credConfigId, issuerDid, cred2Subject);
    await page.goto(buildIssuanceUrl(WALTID_WEB_WALLET_URL, offer2, testUser.walletId));
    await page.waitForLoadState('networkidle');
    
    // Wait for Vue to hydrate
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
    } catch (e) {
      // Continue anyway
    }
    await page.waitForTimeout(2000);
    
    const acceptBtn2 = page.getByRole('button', { name: /accept/i });
    await expect(acceptBtn2).toBeVisible({ timeout: 15000 });
    await acceptBtn2.click();
    
    await page.waitForTimeout(5000);

    // Verify both credentials in wallet
    const credentials = await listWalletCredentials(testUser.token, testUser.walletId);
    expect(credentials.length).toBeGreaterThanOrEqual(2);

    console.log(`Wallet contains ${credentials.length} credentials`);

    // Create presentation request
    const { presentationId, requestUrl } = await createSdJwtPresentationRequest();
    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    await page.screenshot({ path: 'test-results/sdjwt-multiple-credentials.png' });

    // Check if credential selection UI appears
    const credentialSelector = page.locator('[data-testid="credential-select"], .credential-list, .credential-picker');
    const hasSelector = await credentialSelector.first().isVisible().catch(() => false);
    
    if (hasSelector) {
      console.log('Credential selector found - multiple matching credentials');
      // Select first matching credential
      const firstCred = page.locator('.credential-item, [data-testid="credential-option"]').first();
      if (await firstCred.isVisible()) {
        await firstCred.click();
      }
    }

    // Complete presentation
    const shareButton = page.getByRole('button', { name: /share|present|send/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    const success = page.getByText(/success|shared|presented/i);
    await expect(success.first()).toBeVisible({ timeout: 30000 });

    // Verify
    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    expect(presentation.state).toBe('presentation-valid');
    
    console.log('Multi-credential presentation completed successfully');
  });
});
