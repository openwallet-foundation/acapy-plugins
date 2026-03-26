import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

// Load ../demo/.env so env vars (ports, URLs) match the docker-compose stack.
const __filename = fileURLToPath(import.meta.url);
const __dirnamePW = dirname(__filename);
dotenv.config({ path: resolve(__dirnamePW, '../.env') });

/**
 * Playwright configuration for the OID4VC mDOC demo.
 *
 * Defaults to headed (visual) mode so you can watch the demo flow in a real
 * browser. Pass --headless or set CI=true to suppress the window.
 *
 * Usage (from the demo/playwright directory):
 *   npm install
 *   npx playwright install chromium
 *   npx playwright test --headed      # visual demo
 *   npx playwright test               # headless
 *   npx playwright test --ui          # Playwright UI explorer
 */
export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',

  /* Run test files sequentially so the browser window stays visible */
  fullyParallel: false,

  /* No .only checks outside CI */
  forbidOnly: !!process.env.CI,

  /* Retry once in CI */
  retries: process.env.CI ? 1 : 0,

  /* Single worker for a sequential visual demo */
  workers: 1,

  reporter: [
    ['html', { outputFolder: '../test-results/playwright-demo-report', open: 'never' }],
    ['list'],
  ],

  use: {
    /* Walt.id web wallet */
    baseURL: process.env.WALTID_WALLET_URL || 'http://localhost:7101',

    /* Run headed unless CI is set */
    headless: process.env.CI === 'true' || process.env.HEADLESS === 'true',

    /* Slow down actions so a live audience can follow along */
    launchOptions: {
      slowMo: process.env.CI ? 0 : 300,
    },

    /* Capture on failure */
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',

    actionTimeout: 30_000,
    navigationTimeout: 30_000,
  },

  timeout: 180_000,

  expect: {
    timeout: 15_000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  outputDir: '../test-results/playwright-demo-artifacts',
});
