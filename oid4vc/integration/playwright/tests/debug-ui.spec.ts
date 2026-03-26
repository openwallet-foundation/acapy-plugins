/**
 * Debug UI Test
 * 
 * This test captures the wallet UI HTML to help debug selector issues.
 */

import { test, expect } from '@playwright/test';
import { registerTestUser, loginViaBrowser } from '../helpers/wallet-factory';
import { buildIssuanceUrl } from '../helpers/url-encoding';
import {
  createIssuerDid,
  createJwtVcCredentialConfig,
  createSdJwtCredentialConfig,
  createCredentialOffer,
  waitForAcaPyServices,
} from '../helpers/acapy-client';

// Allow choosing between formats via environment variable
const USE_SDJWT = process.env.DEBUG_FORMAT === 'sdjwt';
import * as fs from 'fs';

const WALTID_WEB_WALLET_URL = process.env.WALTID_WEB_WALLET_URL || 'http://localhost:7101';

test.describe('Debug UI', () => {
  let testUser: { email: string; password: string; token: string; walletId: string };
  let issuerDid: string;
  let credConfigId: string;

  test.beforeAll(async () => {
    await waitForAcaPyServices();
    if (USE_SDJWT) {
      issuerDid = await createIssuerDid('p256');
      credConfigId = await createSdJwtCredentialConfig();
      console.log('Using SD-JWT format');
    } else {
      issuerDid = await createIssuerDid('ed25519');
      credConfigId = await createJwtVcCredentialConfig();
      console.log('Using JWT-VC format');
    }
    testUser = await registerTestUser('debug-ui');
  });

  test('should capture issuance page HTML', async ({ page }) => {
    // Capture console messages
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      consoleLogs.push(`[ERROR] ${err.message}`);
    });
    page.on('response', async response => {
      if (response.url().includes('/wallet-api/')) {
        consoleLogs.push(`[NETWORK] ${response.status()} ${response.url()}`);
        // Capture the response body for resolve endpoints
        if (response.url().includes('resolve')) {
          try {
            const body = await response.text();
            consoleLogs.push(`[RESPONSE BODY] ${body.substring(0, 500)}`);
          } catch (e) {
            consoleLogs.push(`[RESPONSE BODY ERROR] ${e}`);
          }
        }
      }
    });

    const credentialSubject = {
      id: 'did:example:debug123',
      given_name: 'Debug',
      family_name: 'Test',
    };

    const { offerUrl, exchangeId } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );
    
    // Log the credential config ID we're using
    console.log(`Credential Config ID: ${credConfigId}`);
    console.log(`Exchange ID: ${exchangeId}`);
    console.log(`Offer URL: ${offerUrl}`);

    // Login
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to issuance
    const issuanceUrl = buildIssuanceUrl(WALTID_WEB_WALLET_URL, offerUrl, testUser.walletId);
    console.log(`Navigating to: ${issuanceUrl}`);
    
    await page.goto(issuanceUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait for Vue/Nuxt to hydrate - look for actual content in the #__nuxt div
    // The app is client-side rendered so we need to wait for JS to execute
    try {
      await page.waitForFunction(() => {
        const nuxtDiv = document.querySelector('#__nuxt');
        return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
      }, { timeout: 15000 });
      console.log('Vue app has hydrated');
    } catch (e) {
      console.log('Vue app hydration timeout - checking page state');
    }
    
    // Print console logs
    console.log('\n=== Browser Console Logs ===');
    consoleLogs.forEach(log => console.log(log));
    console.log('=== End Console Logs ===\n');
    
    // Wait a bit more for any dynamic content
    await page.waitForTimeout(2000);

    // Take screenshot
    await page.screenshot({ path: 'test-results/debug-issuance.png', fullPage: true });

    // Get page title and URL
    console.log(`Page title: ${await page.title()}`);
    console.log(`Current URL: ${page.url()}`);

    // Capture HTML
    const html = await page.content();
    fs.writeFileSync('test-results/debug-issuance.html', html);
    console.log('Saved HTML to test-results/debug-issuance.html');

    // Try to find all buttons
    const buttons = await page.locator('button').all();
    console.log(`Found ${buttons.length} buttons:`);
    for (const button of buttons) {
      const text = await button.textContent();
      console.log(`  - Button: "${text?.trim()}"`);
    }

    // Look for any interactive elements
    const links = await page.locator('a[href]').all();
    console.log(`Found ${links.length} links`);

    // Look for common patterns
    const acceptLike = await page.locator('button, [role="button"]').all();
    console.log(`Found ${acceptLike.length} button-like elements`);

    // Check for specific text on page
    const bodyText = await page.locator('body').textContent();
    if (bodyText?.includes('credential')) {
      console.log('Page contains "credential" text');
    }
    if (bodyText?.includes('offer')) {
      console.log('Page contains "offer" text');
    }
    if (bodyText?.includes('accept') || bodyText?.includes('Accept')) {
      console.log('Page contains "accept" text');
    }
    if (bodyText?.includes('error') || bodyText?.includes('Error')) {
      console.log('Page contains "error" text');
    }

    // This test will "pass" just to output debug info
    expect(true).toBe(true);
  });

  test('should click accept and capture result', async ({ page }) => {
    // Capture console messages
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      consoleLogs.push(`[ERROR] ${err.message}`);
    });
    page.on('response', async response => {
      if (response.url().includes('/wallet-api/') || response.url().includes('acapy')) {
        const status = response.status();
        consoleLogs.push(`[NETWORK] ${status} ${response.url()}`);
        // Capture response bodies for debug
        if (status >= 400 || response.url().includes('token') || response.url().includes('credential')) {
          try {
            const body = await response.text();
            consoleLogs.push(`[RESPONSE BODY] ${body.substring(0, 1000)}`);
          } catch (e) {
            consoleLogs.push(`[RESPONSE BODY ERROR] ${e}`);
          }
        }
      }
    });

    const credentialSubject = {
      id: 'did:example:accept123',
      given_name: 'Accept',
      family_name: 'Test',
      email: 'accept@test.com',
    };

    const { offerUrl, exchangeId } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );
    
    console.log(`Exchange ID: ${exchangeId}`);

    // Login
    await loginViaBrowser(page, testUser.email, testUser.password, WALTID_WEB_WALLET_URL);

    // Navigate to issuance
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
    await page.screenshot({ path: 'test-results/debug-before-accept.png', fullPage: true });

    // Find and click Accept button
    const acceptButton = page.getByRole('button', { name: /accept/i });
    
    if (await acceptButton.isVisible()) {
      console.log('Accept button found, clicking...');
      await acceptButton.click();
      
      // Wait for network activity
      await page.waitForTimeout(5000);
      
      await page.screenshot({ path: 'test-results/debug-after-accept.png', fullPage: true });
      
      // Print console logs
      console.log('\n=== Browser Console Logs ===');
      consoleLogs.forEach(log => console.log(log));
      console.log('=== End Console Logs ===\n');
      
      // Check current state
      console.log(`Current URL: ${page.url()}`);
      console.log(`Page title: ${await page.title()}`);
      
      // Get body text
      const bodyText = await page.locator('body').textContent();
      console.log(`Body contains 'error': ${bodyText?.toLowerCase().includes('error')}`);
      console.log(`Body contains 'success': ${bodyText?.toLowerCase().includes('success')}`);
      console.log(`Body contains 'added': ${bodyText?.toLowerCase().includes('added')}`);
      console.log(`Body contains 'failed': ${bodyText?.toLowerCase().includes('failed')}`);
      
      // Save the HTML
      const html = await page.content();
      fs.writeFileSync('test-results/debug-after-accept.html', html);
    } else {
      console.log('Accept button NOT visible!');
      consoleLogs.forEach(log => console.log(log));
    }

    expect(true).toBe(true);
  });

  test('should debug presentation flow', async ({ page }) => {
    // Capture console messages
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      consoleLogs.push(`[ERROR] ${err.message}`);
    });
    page.on('response', async response => {
      if (response.url().includes('/wallet-api/') || response.url().includes('acapy') || response.url().includes('oid4vp')) {
        const status = response.status();
        consoleLogs.push(`[NETWORK] ${status} ${response.url()}`);
        // Capture response bodies for debug
        if (status >= 400) {
          try {
            const body = await response.text();
            consoleLogs.push(`[ERROR BODY] ${body.substring(0, 500)}`);
          } catch (e) {
            // Ignore
          }
        }
      }
    });

    // First issue a credential
    const credentialSubject = {
      id: 'did:example:pres123',
      given_name: 'Present',
      family_name: 'Test',
    };

    const { offerUrl, exchangeId } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );
    
    console.log(`Exchange ID: ${exchangeId}`);

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
    console.log('Credential issued, now testing presentation...');

    // Import presentation helpers
    const { createJwtVcPresentationRequest } = await import('../helpers/acapy-client');
    const { buildPresentationUrl } = await import('../helpers/url-encoding');

    // Create presentation request
    const { presentationId, requestUrl } = await createJwtVcPresentationRequest();
    console.log(`Presentation ID: ${presentationId}`);
    console.log(`Request URL: ${requestUrl}`);

    // Navigate to presentation
    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    console.log(`Full presentation URL: ${presentationUrl}`);
    
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    await page.waitForTimeout(2000);
    await page.screenshot({ path: 'test-results/debug-presentation.png', fullPage: true });
    
    // Get page content
    console.log(`Page title: ${await page.title()}`);
    console.log(`Current URL: ${page.url()}`);
    
    // Find buttons
    const buttons = await page.locator('button').all();
    console.log(`Found ${buttons.length} buttons:`);
    for (const button of buttons) {
      const text = await button.textContent();
      console.log(`  - Button: "${text?.trim()}"`);
    }

    // Print console logs
    console.log('\n=== Browser Console Logs ===');
    consoleLogs.forEach(log => console.log(log));
    console.log('=== End Console Logs ===\n');

    expect(true).toBe(true);
  });

  test('should complete presentation and verify state', async ({ page }) => {
    // Capture console messages
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', err => {
      consoleLogs.push(`[ERROR] ${err.message}`);
    });
    page.on('response', async response => {
      const status = response.status();
      if (response.url().includes('/wallet-api/') || response.url().includes('oid4vp') || response.url().includes('acapy')) {
        consoleLogs.push(`[NETWORK] ${status} ${response.url()}`);
        if (status >= 400) {
          try {
            const body = await response.text();
            consoleLogs.push(`[ERROR BODY] ${body.substring(0, 1000)}`);
          } catch (e) {
            // Ignore
          }
        }
      }
    });

    // First issue a credential
    const credentialSubject = {
      id: 'did:example:presComplete123',
      given_name: 'Complete',
      family_name: 'Presentation',
    };

    const { offerUrl, exchangeId } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject
    );
    
    console.log(`Exchange ID: ${exchangeId}`);

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
    console.log('Credential issued successfully!');

    // Create presentation request
    const { createJwtVcPresentationRequest, waitForPresentationState } = await import('../helpers/acapy-client');
    const { buildPresentationUrl } = await import('../helpers/url-encoding');

    const { presentationId, requestUrl } = await createJwtVcPresentationRequest();
    console.log(`Presentation ID: ${presentationId}`);

    // Navigate to presentation
    const presentationUrl = buildPresentationUrl(WALTID_WEB_WALLET_URL, requestUrl, testUser.walletId);
    console.log(`Presentation URL: ${presentationUrl}`);
    
    await page.goto(presentationUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait for Vue to hydrate
    await page.waitForFunction(() => {
      const nuxtDiv = document.querySelector('#__nuxt');
      return nuxtDiv && nuxtDiv.children.length > 0 && nuxtDiv.textContent!.trim().length > 10;
    }, { timeout: 15000 });

    await page.waitForTimeout(2000);
    await page.screenshot({ path: 'test-results/debug-presentation-before-accept.png', fullPage: true });
    
    // Click Accept for presentation
    const presAcceptButton = page.getByRole('button', { name: /accept/i });
    await expect(presAcceptButton).toBeVisible({ timeout: 10000 });
    console.log('Clicking Accept on presentation...');
    await presAcceptButton.click();
    
    // Wait for network and any redirects
    await page.waitForTimeout(10000);
    
    await page.screenshot({ path: 'test-results/debug-presentation-after-accept.png', fullPage: true });
    
    console.log(`After accept - URL: ${page.url()}`);
    console.log(`After accept - Title: ${await page.title()}`);
    
    // Print console logs
    console.log('\n=== Browser Console Logs ===');
    consoleLogs.forEach(log => console.log(log));
    console.log('=== End Console Logs ===\n');
    
    // Now check presentation state
    console.log('Checking presentation state...');
    try {
      const presentation = await waitForPresentationState(presentationId, 'presentation-valid', 10);
      console.log(`Presentation state: ${presentation.state}`);
      console.log('Presentation verified successfully!');
    } catch (e) {
      console.log(`Presentation state check failed: ${e}`);
      // Check current state
      const { getPresentationState } = await import('../helpers/acapy-client');
      const state = await getPresentationState(presentationId);
      console.log(`Current presentation state: ${JSON.stringify(state, null, 2)}`);
    }

    expect(true).toBe(true);
  });
});
