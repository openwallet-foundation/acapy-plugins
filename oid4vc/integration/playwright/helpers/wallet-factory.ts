/**
 * Wallet Factory - Creates unique test users and wallets for walt.id testing.
 * 
 * Each test file should create its own user/wallet to enable parallel test execution.
 */

import axios from 'axios';
import type { AxiosInstance } from 'axios';
import type { BrowserContext, Page } from '@playwright/test';

const WALLET_API_URL = process.env.WALTID_WALLET_API_URL || 'http://localhost:7001';

interface WalletUser {
  email: string;
  password: string;
  token: string;
  walletId: string;
}

interface AuthResponse {
  token: string;
}

interface WalletsResponse {
  wallets: Array<{
    id: string;
    name: string;
  }>;
}

/**
 * Generate a unique email for test isolation
 */
function generateTestEmail(prefix?: string): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  const prefixPart = prefix ? `${prefix}-` : '';
  return `test-${prefixPart}${timestamp}-${random}@playwright.local`;
}

/**
 * Create an axios client for the wallet API
 */
function createApiClient(token?: string): AxiosInstance {
  const client = axios.create({
    baseURL: WALLET_API_URL,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
    timeout: 30000,
  });
  return client;
}

/**
 * Register a new test user with the walt.id wallet
 */
export async function registerTestUser(prefix?: string): Promise<WalletUser> {
  const email = generateTestEmail(prefix);
  const password = 'TestPassword123!';
  const name = `Test User ${Date.now()}`;
  
  const client = createApiClient();
  
  // Register user - walt.id requires name, email, password, and type
  await client.post('/wallet-api/auth/register', {
    name,
    email,
    password,
    type: 'email',
  });
  
  // Login to get token
  const loginResponse = await client.post<AuthResponse>('/wallet-api/auth/login', {
    type: 'email',
    email,
    password,
  });
  
  const token = loginResponse.data.token;
  
  // Get wallet ID
  const authedClient = createApiClient(token);
  const walletsResponse = await authedClient.get<WalletsResponse>('/wallet-api/wallet/accounts/wallets');
  
  if (!walletsResponse.data.wallets || walletsResponse.data.wallets.length === 0) {
    throw new Error('No wallets found for user');
  }
  
  const walletId = walletsResponse.data.wallets[0].id;
  
  return {
    email,
    password,
    token,
    walletId,
  };
}

/**
 * Create a DID for the wallet user
 */
export async function createWalletDid(user: WalletUser, method: string = 'key'): Promise<string> {
  const client = createApiClient(user.token);
  
  const response = await client.post<{ did: string }>(`/wallet-api/wallet/${user.walletId}/dids/create/${method}`);
  
  return response.data.did;
}

/**
 * List credentials in the wallet
 * @param token - Auth token or WalletUser object
 * @param walletId - Wallet ID (required if token is a string)
 */
export async function listWalletCredentials(tokenOrUser: string | WalletUser, walletId?: string): Promise<any[]> {
  let token: string;
  let wId: string;
  
  if (typeof tokenOrUser === 'string') {
    token = tokenOrUser;
    if (!walletId) {
      throw new Error('walletId is required when passing token as string');
    }
    wId = walletId;
  } else {
    token = tokenOrUser.token;
    wId = tokenOrUser.walletId;
  }
  
  const client = createApiClient(token);
  
  const response = await client.get<any[]>(`/wallet-api/wallet/${wId}/credentials`);
  
  return response.data;
}

/**
 * Inject authentication cookies into Playwright browser context.
 * 
 * This allows the browser to be authenticated as the test user.
 */
export async function injectAuthContext(context: BrowserContext, user: WalletUser): Promise<void> {
  // walt.id uses localStorage for auth token, so we need to set it via page script
  const page = await context.newPage();
  
  await page.goto(process.env.WALTID_WALLET_URL || 'http://localhost:7101');
  
  // Set the auth token in localStorage
  await page.evaluate((token) => {
    localStorage.setItem('waltid_token', token);
  }, user.token);
  
  // Also set a cookie for API requests
  await context.addCookies([
    {
      name: 'waltid_session',
      value: user.token,
      domain: new URL(process.env.WALTID_WALLET_URL || 'http://localhost:7101').hostname,
      path: '/',
      httpOnly: false,
      secure: false,
      sameSite: 'Lax',
    },
  ]);
  
  await page.close();
}

/**
 * Login to wallet via browser.
 * 
 * This uses the API to authenticate and injects the token as a cookie,
 * which is more reliable than UI-based login for E2E testing.
 * 
 * @param page - Playwright Page object
 * @param email - User email
 * @param password - User password
 * @param baseUrl - Wallet base URL
 */
export async function loginViaBrowser(
  page: Page,
  email: string,
  password: string,
  baseUrl?: string
): Promise<void> {
  const walletUrl = baseUrl || process.env.WALTID_WALLET_URL || 'http://localhost:7101';
  const walletApiUrl = process.env.WALTID_WALLET_API_URL || 'http://localhost:7001';
  
  // Authenticate via API (more reliable than UI login)
  const client = createApiClient();
  const loginPayload = {
    name: 'Test User',
    email,
    password,
    type: 'email',
  };
  
  const loginResponse = await client.post<{ token: string }>('/wallet-api/auth/login', loginPayload);
  const token = loginResponse.data.token;
  
  // Parse the wallet URL to get the domain for cookies
  const walletUrlObj = new URL(walletUrl);
  
  // Set auth cookie in browser context - use the exact cookie name nuxt-auth expects
  await page.context().addCookies([
    {
      name: 'auth.token',
      value: token,
      domain: walletUrlObj.hostname,
      path: '/',
      httpOnly: false,
      secure: false,
      sameSite: 'Lax',
    },
  ]);
  
  // Add route handler to inject Authorization header for all wallet-api requests
  // This ensures the Bearer token is sent with every request
  await page.route('**/wallet-api/**', async (route) => {
    const headers = {
      ...route.request().headers(),
      'Authorization': `Bearer ${token}`,
    };
    await route.continue({ headers });
  });
  
  // Navigate to wallet after setting cookie
  await page.goto(walletUrl);
  await page.waitForLoadState('networkidle');
  
  // Set token in localStorage as well
  await page.evaluate((authToken) => {
    localStorage.setItem('auth.token', authToken);
    localStorage.setItem('auth._token.local', `Bearer ${authToken}`);
    console.log('Auth token set in localStorage');
  }, token);
  
  // Wait for auth to initialize
  await page.waitForTimeout(500);
}

/**
 * Wait for wallet API to be healthy
 */
export async function waitForWalletApi(maxRetries: number = 30): Promise<void> {
  const client = createApiClient();
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      await client.get('/wallet-api/health');
      return;
    } catch (error) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  throw new Error('Wallet API not available after max retries');
}
