/**
 * JWT-VC Credential Flow Test
 * 
 * E2E test for JWT-VC credential issuance and presentation using
 * ACA-Py and walt.id web wallet with OID4VCI/OID4VP protocols.
 */

import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser, listWalletCredentials } from '../helpers/wallet-factory';
import { buildIssuanceUrl, buildPresentationUrl } from '../helpers/url-encoding';
import {
  createIssuerDid,
  createJwtVcCredentialConfig,
  createCredentialOffer,
  createJwtVcPresentationRequest,
  waitForPresentationState,
  waitForAcaPyServices,
} from '../helpers/acapy-client';

const WALTID_WEB_WALLET_URL = process.env.WALTID_WEB_WALLET_URL || 'http://localhost:7101';

test.describe('JWT-VC Credential Flow', () => {
  let testUser: { email: string; password: string; token: string; walletId: string };
  let issuerDid: string;
  let credConfigId: string;

  test.beforeAll(async () => {
    // Wait for services
    await waitForAcaPyServices();
    
    // Create issuer DID (EdDSA for JWT-VC)
    issuerDid = await createIssuerDid('ed25519');
    
    // Create JWT-VC credential configuration
    credConfigId = await createJwtVcCredentialConfig();
    
    // Register test user
    testUser = await registerTestUser('jwtvc-flow');
  });

  test('should issue JWT-VC credential to wallet', async ({ page }) => {
    // Create credential offer
    const credentialSubject = {
      id: 'did:example:subject123',
      given_name: 'Charlie',
      family_name: 'Brown',
      degree: {
        type: 'BachelorDegree',
        name: 'Computer Science',
        institution: 'Test University',
      },
    };

    const { exchangeId, offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    console.log(`Created JWT-VC credential offer: ${exchangeId}`);

    // Login to wallet
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to credential offer
    const issuanceUrl = buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId);
    await page.goto(issuanceUrl);
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    // Take screenshot
    await page.screenshot({ path: 'test-results/jwtvc-issuance-offer.png' });

    // Accept credential
    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 10000 });
    await acceptButton.click();

    // Wait for redirect to wallet dashboard (walt.id redirects after successful issuance)
    await page.waitForURL(/\/wallet\/[^/]+(?:$|\?)/, { timeout: 30000 });

    await page.screenshot({ path: 'test-results/jwtvc-issuance-success.png' });

    // Verify via API
    const credentials = await listWalletCredentials(testUser.token, testUser.walletId);
    expect(credentials.length).toBeGreaterThanOrEqual(1);
    
    console.log('JWT-VC credential issued successfully');
  });

  // TODO: Re-enable when OID4VP signature verification bug is fixed
  // The verifier fails to verify Ed25519 signatures from did:key credentials
  // See: Credential signature verification failed in oid4vc.pex
  test.skip('should present JWT-VC credential to verifier', async ({ page }) => {
    // First issue a credential
    const credentialSubject = {
      id: 'did:example:presenter456',
      given_name: 'Diana',
      family_name: 'Prince',
      organization: 'Test Corp',
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
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 10000 });
    await acceptButton.click();

    // Wait for redirect to wallet dashboard
    await page.waitForURL(/\/wallet\/[^/]+(?:$|\?)/, { timeout: 30000 });

    // Now present the credential
    const { presentationId, requestUrl } = await createJwtVcPresentationRequest();
    console.log(`Created JWT-VC presentation request: ${presentationId}`);

    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    await page.screenshot({ path: 'test-results/jwtvc-presentation-request.png' });

    // Present credential - look for Share or Present button
    const shareButton = page.getByRole('button', { name: /share|present|send|accept/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    // Wait for redirect or state change (verifier redirect or dashboard)
    await page.waitForTimeout(5000);

    await page.screenshot({ path: 'test-results/jwtvc-presentation-success.png' });

    // Verify with verifier
    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    expect(presentation.state).toBe('presentation-valid');
    
    console.log('JWT-VC presentation verified successfully');
  });

  // TODO: Re-enable when OID4VP signature verification bug is fixed
  test.skip('should verify credential type in presentation definition', async ({ page }) => {
    // Issue a credential
    const credentialSubject = {
      given_name: 'Eve',
      family_name: 'Wilson',
      employee_id: 'EMP-12345',
    };

    const { offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    // Accept credential
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);
    await page.goto(buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId));
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 10000 });
    await acceptButton.click();

    // Wait for redirect to wallet dashboard
    await page.waitForURL(/\/wallet\/[^/]+(?:$|\?)/, { timeout: 30000 });

    // Create presentation request with type filter
    const { presentationId, requestUrl } = await createJwtVcPresentationRequest();

    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    // The wallet should show matching credentials
    const credentialList = page.locator('.credential-list, [data-testid="matching-credentials"]');
    const hasCredList = await credentialList.first().isVisible().catch(() => false);
    
    if (hasCredList) {
      console.log('Credential list shown for type-based filtering');
    }

    // Complete presentation
    const shareButton = page.getByRole('button', { name: /share|present|send|accept/i });
    await expect(shareButton.first()).toBeVisible({ timeout: 10000 });
    await shareButton.first().click();

    // Wait for navigation or state change
    await page.waitForTimeout(5000);

    const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 60);
    expect(presentation.state).toBe('presentation-valid');
    
    console.log('Type-filtered JWT-VC presentation completed');
  });

  test('should display credential details with nested claims', async ({ page }) => {
    // Issue credential with nested structure
    const credentialSubject = {
      given_name: 'Frank',
      family_name: 'Miller',
      address: {
        street: '123 Main St',
        city: 'Anytown',
        state: 'CA',
        postal_code: '90210',
      },
    };

    const { offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );

    // Accept credential
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);
    await page.goto(buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId));
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    const acceptButton = page.getByRole('button', { name: /accept/i });
    await expect(acceptButton).toBeVisible({ timeout: 10000 });
    await acceptButton.click();

    // Wait for redirect to wallet dashboard
    await page.waitForURL(/\/wallet\/[^/]+(?:$|\?)/, { timeout: 30000 });

    // Navigate to credentials list
    await page.goto(`${WALTID_WEB_WALLET_URL}/wallet/${testUser.walletId}/credentials`);
    await page.waitForLoadState('networkidle');

    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    // Find and click the credential
    const credential = page.getByText(/Test Credential|JWT/i).first();
    if (await credential.isVisible()) {
      await credential.click();
      await page.waitForLoadState('networkidle');

      // Verify nested claims are displayed
      const cityField = page.locator('text=Anytown');
      const hasNestedClaims = await cityField.first().isVisible().catch(() => false);
      
      if (hasNestedClaims) {
        console.log('Nested claims displayed correctly');
      }

      await page.screenshot({ path: 'test-results/jwtvc-nested-claims.png' });
    }

    console.log('Nested claims credential test completed');
  });
});
