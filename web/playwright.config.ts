// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from '@playwright/test';

// The e2e tests run the production build (vite preview, with the control
// plane's CSP headers) against a mocked API (e2e/mockApi.ts).
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://localhost:4173',
    locale: 'en-US',
    timezoneId: 'Asia/Ho_Chi_Minh',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
      testIgnore: /screenshots\.spec\.ts/,
    },
    {
      name: 'screenshots',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 },
      testMatch: /screenshots\.spec\.ts/,
    },
  ],
  webServer: {
    command: 'npx vite build && npx vite preview --port 4173 --strictPort',
    url: 'http://localhost:4173/ui/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
