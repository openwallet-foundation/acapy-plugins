import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for OID4VC E2E tests with walt.id web wallet.
 * 
 * Run tests:
 *   npx playwright test
 * 
 * Run with UI:
 *   npx playwright test --ui
 */
export default defineConfig({
  testDir: './tests',
  
  /* Run tests in files in parallel - each file gets its own user/wallet */
  fullyParallel: true,
  
  /* Fail the build on CI if you accidentally left test.only in the source code */
  forbidOnly: !!process.env.CI,
  
  /* Retry on failure */
  retries: process.env.CI ? 1 : 0,
  
  /* Parallel workers - each test file gets its own user */
  workers: process.env.CI ? 2 : 4,
  
  /* Reporter configuration */
  reporter: [
    ['html', { outputFolder: '../test-results/playwright-report' }],
    ['junit', { outputFile: '../test-results/playwright-junit.xml' }],
    ['list']
  ],
  
  /* Shared settings for all projects */
  use: {
    /* Base URL for walt.id web wallet */
    baseURL: process.env.WALTID_WALLET_URL || 'http://localhost:7101',
    
    /* Collect trace on failure for debugging */
    trace: 'retain-on-failure',
    
    /* Record video on failure */
    video: 'retain-on-failure',
    
    /* Screenshot on failure */
    screenshot: 'only-on-failure',
    
    /* Increase timeout for wallet operations */
    actionTimeout: 30000,
    navigationTimeout: 30000,
  },

  /* Global timeout for each test */
  timeout: 120000,
  
  /* Expect timeout */
  expect: {
    timeout: 10000,
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        // Headless mode for CI
        headless: true,
      },
    },
  ],

  /* Output directory for test artifacts */
  outputDir: '../test-results/playwright-artifacts',

  /* Global setup - could be used to wait for services */
  // globalSetup: require.resolve('./global-setup'),
});
