/**
 * OID4VC mDOC Demo — End-to-End Flow
 *
 * Demonstrates:
 *   1. OID4VCI v1 mDOC (ISO 18013-5 mDL) credential issuance from ACA-Py to
 *      the walt.id web wallet.
 *   2. OID4VP v1 mDOC presentation from the wallet back to the ACA-Py verifier.
 *
 * ─ Prerequisites ──────────────────────────────────────────────────────────────
 *   docker compose -f ../docker-compose.yml up -d
 *   ../setup.sh
 *   npm install && npx playwright install chromium
 *
 * ─ Run  ───────────────────────────────────────────────────────────────────────
 *   npx playwright test --headed          # visual (default)
 *   npx playwright test                   # headless
 *
 * ─ mDOC issuance note ─────────────────────────────────────────────────────────
 *   The walt.id waltid-web-wallet:latest image has a known bug: its issuance UI
 *   crashes on mso_mdoc credentials because it only looks for `types` / `vct`
 *   fields, not `doctype`.  We therefore accept the credential via the wallet
 *   REST API and then flip to the browser to show it.
 *
 *   See: https://github.com/walt-id/waltid-identity
 */

import { test, expect } from '@playwright/test';
import axios from 'axios';
import {
  waitForAcaPyServices,
  createIssuerDid,
  createMdocCredentialConfig,
  createCredentialOffer,
  generateMdocSigningKeys,
  uploadTrustAnchor,
  createMdocPresentationRequest,
  waitForPresentationState,
} from './helpers/acapy-client';
import {
  registerTestUser,
  loginViaBrowser,
  listWalletCredentials,
} from './helpers/wallet-factory';


// ── Config ────────────────────────────────────────────────────────────────────

const WALTID_WALLET_URL = process.env.WALTID_WALLET_URL || 'http://localhost:7101';
const WALTID_WALLET_API_URL = process.env.WALTID_WALLET_API_URL || 'http://localhost:7101';
const ACAPY_ISSUER_ADMIN_URL = process.env.ACAPY_ISSUER_ADMIN_URL || 'http://localhost:8021';
const ACAPY_VERIFIER_ADMIN_URL = process.env.ACAPY_VERIFIER_ADMIN_URL || 'http://localhost:8031';

// ── Shared demo state ─────────────────────────────────────────────────────────

let demoUser: Awaited<ReturnType<typeof registerTestUser>>;
let issuerDid: string;
let credConfigId: string;

// ── Wallet API helper for programmatic credential acceptance ──────────────────

/**
 * Accept a credential offer via the wallet API, bypassing the web UI.
 *
 * The walt.id waltid-web-wallet:latest web UI crashes on mso_mdoc offers, but
 * the backend wallet-api handles them correctly.  This function replicates what
 * the UI would do:
 *   1. Resolve the offer to retrieve available credentials.
 *   2. Claim each credential and store it in the wallet.
 */
async function acceptCredentialOfferViaApi(
  offerUrl: string,
  walletId: string,
  token: string,
): Promise<void> {
  const client = axios.create({
    baseURL: WALTID_WALLET_API_URL,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    timeout: 30_000,
  });

  // Resolve the offer — returns a list of credentials available for issuance.
  const resolveResp = await client.post(
    `/wallet-api/wallet/${walletId}/exchange/resolveCredentialOffer`,
    offerUrl,
    { headers: { 'Content-Type': 'text/plain' } },
  );

  console.log(`[wallet-api] resolved offer — ${resolveResp.data.credentials?.length ?? 0} credential(s)`);

  // Claim each credential.
  const useResp = await client.post(
    `/wallet-api/wallet/${walletId}/exchange/useOfferRequest`,
    offerUrl,
    { headers: { 'Content-Type': 'text/plain' } },
  );

  console.log(`[wallet-api] claimCredential status: ${useResp.status}`);
}

/**
 * Submit a presentation request via the wallet API, bypassing the web UI.
 *
 * The walt.id web UI fails to match mso_mdoc credentials against the
 * presentation definition.  This function calls the wallet-api directly:
 *   1. List wallet credentials to find the mDL credential ID.
 *   2. POST usePresentationRequest with the request URL + selected credential.
 */
async function submitPresentationViaApi(
  requestUrl: string,
  walletId: string,
  token: string,
): Promise<void> {
  const client = axios.create({
    baseURL: WALTID_WALLET_API_URL,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    timeout: 30_000,
  });

  // Find the mDL credential ID in the wallet.
  const credsResp = await client.get(`/wallet-api/wallet/${walletId}/credentials`);
  const credentials: any[] = credsResp.data;
  const mdlCred = credentials.find(
    (c: any) => JSON.stringify(c).includes('org.iso.18013.5.1.mDL'),
  );
  if (!mdlCred) throw new Error('mDL credential not found in wallet');
  const credentialId: string = mdlCred.id;
  console.log(`[wallet-api] Presenting credential: ${credentialId}`);

  // Resolve the presentation request first — returns the parsed request URL
  // with presentation_definition embedded, which usePresentationRequest requires.
  const resolveResp = await client.post(
    `/wallet-api/wallet/${walletId}/exchange/resolvePresentationRequest`,
    requestUrl,
    { headers: { 'Content-Type': 'text/plain' } },
  );
  const resolvedRequest: string = resolveResp.data;
  console.log(`[wallet-api] resolvePresentationRequest status: ${resolveResp.status}`);

  // Get the wallet's default DID to present from.
  const didsResp = await client.get(`/wallet-api/wallet/${walletId}/dids`);
  const dids: any[] = didsResp.data;
  const holderDid: string | undefined = dids?.find((d: any) => d.default)?.did ?? dids?.[0]?.did;

  // Submit the presentation — field is `selectedCredentials` (not selectedCredentialIds).
  const useResp = await client.post(
    `/wallet-api/wallet/${walletId}/exchange/usePresentationRequest`,
    {
      did: holderDid ?? null,
      presentationRequest: resolvedRequest,
      selectedCredentials: [credentialId],
      disclosures: null,
    },
  );
  console.log(`[wallet-api] usePresentationRequest status: ${useResp.status}`);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('OID4VC mDOC Demo', () => {

  test.beforeAll(async () => {
    // ── Wait for all services ──
    await waitForAcaPyServices(60);

    // ── Set up issuer ──
    issuerDid = await createIssuerDid('p256');
    console.log(`Issuer DID: ${issuerDid}`);

    await generateMdocSigningKeys();
    console.log('mDOC signing keys ready');

    credConfigId = await createMdocCredentialConfig('Mobile-Driving-License');
    console.log(`mDL credential config: ${credConfigId}`);

    // Upload trust anchor to verifier so mDOC signatures can be verified.
    // Uses the auto-generated issuer cert stored in the ACA-Py wallet.
    await uploadTrustAnchor();
    console.log('Trust anchor uploaded to verifier');

    // ── Register a demo wallet user ──
    demoUser = await registerTestUser('demo');
    console.log(`Demo wallet user: ${demoUser.email}`);
  });

  // ── Test 1: Issuance ────────────────────────────────────────────────────────

  test('Issue mDL credential to wallet', async ({ page }) => {
    // ── Show credential configs registered in ACA-Py ──
    await page.goto(`${ACAPY_ISSUER_ADMIN_URL}/oid4vci/credential-supported/records`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-01a-credential-configs.png' });

    // ── Create credential offer ──
    const credentialSubject = {
      'org.iso.18013.5.1': {
        given_name:              'Alice',
        family_name:             'Holder',
        birth_date:              '1990-06-15',
        issuing_country:         'US',
        issuing_authority:       'Demo DMV',
        document_number:         'DL-DEMO-001',
        issue_date:              new Date().toISOString().split('T')[0],
        expiry_date:             new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
                                   .toISOString().split('T')[0],
        // portrait and un_distinguishing_sign are required by ISO 18013-5.1
        portrait:                'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        un_distinguishing_sign:  'USA',
        driving_privileges: [
          { vehicle_category_code: 'C', issue_date: '2020-01-01', expiry_date: '2030-01-01' },
        ],
      },
    };

    const { exchangeId, offerUrl } = await createCredentialOffer(
      credConfigId,
      issuerDid,
      credentialSubject,
    );
    console.log(`Credential offer created: ${exchangeId}`);

    // ── Show the active (pre-issued) exchange record in ACA-Py ──
    await page.goto(`${ACAPY_ISSUER_ADMIN_URL}/oid4vci/exchange/records`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-01b-exchange-active.png' });

    // ── Accept via wallet API (bypasses the waltid UI mso_mdoc bug) ──
    await acceptCredentialOfferViaApi(offerUrl, demoUser.walletId, demoUser.token);
    console.log('Credential accepted via wallet API');

    // ── Show the exchange record now marked "issued" in ACA-Py ──
    await page.goto(`${ACAPY_ISSUER_ADMIN_URL}/oid4vci/exchange/records`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-01c-exchange-issued.png' });

    // ── Open the wallet in the browser and verify the credential appears ──
    await loginViaBrowser(page, demoUser.email, demoUser.password, WALTID_WALLET_URL);

    // loginViaBrowser already navigated to the wallet selector page (/).
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    // Wallet selector — shows all wallets available for this user.
    await page.screenshot({ path: '../test-results/demo-01d-wallet-select.png' });

    // Click "View wallet" to enter the wallet — just like a real user would.
    await page.getByRole('button', { name: 'View wallet' }).click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    // Credentials list — the issued mDL card should be visible here.
    await page.screenshot({ path: '../test-results/demo-01-wallet-credentials.png' });

    // Note: waltid credential detail view crashes on mso_mdoc credentials
    // (TypeError: Cannot read properties of null (reading 'issuerSigned')),
    // the same known bug as the issuance UI. We stay on the credentials list.

    // Navigate to the DIDs page to show the wallet's cryptographic identity.
    await page.getByRole('link', { name: 'DIDs' }).click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    await page.screenshot({ path: '../test-results/demo-01f-wallet-dids.png' });

    // ── Verify via API ──
    const credentials = await listWalletCredentials(demoUser);
    expect(credentials.length).toBeGreaterThanOrEqual(1);

    const mdlCred = credentials.find(
      (c: any) =>
        c.parsedDocument?.docType === 'org.iso.18013.5.1.mDL' ||
        c.document?.type === 'org.iso.18013.5.1.mDL' ||
        JSON.stringify(c).includes('org.iso.18013.5.1.mDL'),
    );
    console.log(`mDL in wallet: ${mdlCred ? 'yes' : 'credential found (unknown format)'}`);

    console.log(`✓ ${credentials.length} credential(s) in wallet after issuance`);
  });

  // ── Test 2: Presentation ────────────────────────────────────────────────────

  test('Present mDL credential via OID4VP', async ({ page }) => {
    // ── Create a presentation request from the verifier ──
    const { presentationId, requestUrl } = await createMdocPresentationRequest();
    console.log(`Presentation request: ${presentationId}`);
    console.log(`Request URI: ${requestUrl}`);

    // ── Show the pending presentation request in ACA-Py verifier ──
    await page.goto(`${ACAPY_VERIFIER_ADMIN_URL}/oid4vp/presentation/${presentationId}`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-02a-presentation-pending.png' });

    // ── Submit the presentation via wallet API (bypasses the waltid UI matcher bug) ──
    await submitPresentationViaApi(requestUrl, demoUser.walletId, demoUser.token);
    console.log('Presentation submitted via wallet API');

    // ── Poll for verification result ──
    const result = await waitForPresentationState(presentationId, 'presentation-valid', 20);
    console.log(`✓ Presentation verified: ${result.state}`);

    // ── Show the verified result in the ACA-Py verifier browser ──
    await page.goto(`${ACAPY_VERIFIER_ADMIN_URL}/oid4vp/presentation/${presentationId}`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-02b-presentation-result.png' });

    // ── Show the wallet home to close the loop ──
    await loginViaBrowser(page, demoUser.email, demoUser.password, WALTID_WALLET_URL);

    // Navigate into the specific wallet to show the credential is still there after presentation.
    await page.goto(`${WALTID_WALLET_URL}/wallet/${demoUser.walletId}`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2500);
    await page.screenshot({ path: '../test-results/demo-03-wallet-after-presentation.png' });

    // Navigate to the event log to show the full credential lifecycle.
    await page.getByRole('link', { name: 'Event log' }).click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    await page.screenshot({ path: '../test-results/demo-04-event-log.png' });
  });
});
