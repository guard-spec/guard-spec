// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { test as base, expect, type Page } from '@playwright/test';
import { EMAIL, installMockApi, PASSWORD, seedState, type MockOptions, type MockState } from './mockApi';

declare global {
  interface Window {
    __cspViolations?: string[];
  }
}

/**
 * Every test gets the mocked API and fails on a CSP violation or an uncaught
 * page error: the build must run under default-src 'self'.
 */
export const test = base.extend<{ mock: MockState; mockOptions: MockOptions }>({
  mockOptions: [{}, { option: true }],
  mock: [
    async ({ page, mockOptions }, use) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    page.on('console', (m) => {
      if (m.type() === 'error' && /Content.Security.Policy|Refused to/i.test(m.text())) errors.push(`console: ${m.text()}`);
    });
    await page.addInitScript(() => {
      window.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        window.__cspViolations?.push(`${e.violatedDirective} ${e.blockedURI} ${e.sourceFile}:${e.lineNumber}:${e.columnNumber} ${e.sample}`);
      });
    });
    const state = await installMockApi(page, seedState(), mockOptions);
    await use(state);
    const violations = await page.evaluate(() => window.__cspViolations ?? []).catch(() => [] as string[]);
    expect([...errors, ...violations], 'CSP violations and page errors').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/**
 * Picks the first organization of the user's list, or opens the prefilled
 * default org id when the control plane has no list.
 */
export async function chooseOrg(page: Page, openLabel = 'Open'): Promise<void> {
  const item = page.getByTestId('my-orgs').getByRole('button').first();
  const byId = page.getByRole('button', { name: openLabel, exact: true });
  await expect(item.or(byId).first()).toBeVisible();
  // The list loads after the page: give it a moment before falling back.
  try {
    await item.click({ timeout: 2000 });
  } catch {
    await byId.click();
  }
}

export async function login(page: Page): Promise<void> {
  await page.goto('/ui/');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await chooseOrg(page);
  await expect(page.getByRole('heading', { name: 'Flow', level: 1 })).toBeVisible();
}
