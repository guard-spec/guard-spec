// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Screenshots of every page of the admin UI v2, light and dark, desktop and
// mobile, against the mocked API with more data:
//   SHOTS_DIR=/some/dir npx playwright test --project=screenshots ui-v2
// Without SHOTS_DIR they go to test-results/ui-v2 (not committed).

import type { Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { chooseOrg, expect, go, login, openProfile, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const OUT = (process.env.SHOTS_DIR ?? 'test-results/ui-v2').replace(/\/$/, '');
mkdirSync(OUT, { recursive: true });

const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  mobile: { width: 390, height: 844 },
} as const;

type Theme = 'light' | 'dark';
type Vp = keyof typeof VIEWPORTS;

async function prepare(page: Page, theme: Theme, vp: Vp) {
  await page.setViewportSize(VIEWPORTS[vp]);
  await page.addInitScript((t) => localStorage.setItem('gs.theme', t), theme);
}

async function shot(page: Page, name: string, theme: Theme, vp: Vp, fullPage = false) {
  await page.waitForTimeout(350);
  await page.screenshot({ path: `${OUT}/${name}-${theme}-${vp}.png`, animations: 'disabled', fullPage });
}

/** Opens a page: from the sidebar on desktop, through the drawer on mobile. */
async function open(page: Page, vp: Vp, name: string) {
  if (vp === 'mobile') await page.getByRole('button', { name: 'Open menu' }).click();
  await go(page, name);
}

test.use({ mockOptions: { rich: true } });

for (const theme of ['light', 'dark'] as const) {
  for (const vp of ['desktop', 'mobile'] as const) {
    test.describe(`${theme} ${vp}`, () => {
      test('login', async ({ page }) => {
        await prepare(page, theme, vp);
        await page.goto('/ui/');
        await expect(page.getByTestId('sso-buttons')).toBeVisible();
        await shot(page, 'login', theme, vp);
      });

      test('pages', async ({ page }) => {
        test.setTimeout(120_000);
        await prepare(page, theme, vp);
        await login(page, null);
        await expect(page.getByTestId('dash-range')).toBeVisible();
        await shot(page, 'dashboard', theme, vp, vp === 'desktop');
        const pages: [string, string][] = [
          ['Policy flow', 'flow'],
          ['Model providers', 'providers'],
          ['Request log', 'requests'],
          ['Activity log', 'activity'],
          ['Members', 'members'],
          ['Roles and permissions', 'roles'],
          ['Security', 'security'],
          ['API keys', 'keys'],
          ['Simulator', 'simulator'],
          ['Users', 'admin-users'],
          ['Identity providers', 'identity-providers'],
          ['Instance activity', 'admin-activity'],
        ];
        for (const [label, file] of pages) {
          await open(page, vp, label);
          await shot(page, file, theme, vp);
        }
        await open(page, vp, 'Model providers');
        await page.getByRole('button', { name: 'Test connection of main' }).click();
        await expect(page.getByTestId('test-result').first()).toBeVisible();
        await shot(page, 'providers-tested', theme, vp);
        await page.getByRole('button', { name: 'Add provider' }).click();
        await shot(page, 'provider-catalog', theme, vp);
        await page.getByTestId('provider-catalog').getByRole('button', { name: /^OpenAI https/ }).click();
        await page.getByRole('dialog').getByRole('button', { name: '+ gpt-4o', exact: true }).click();
        await page.getByRole('dialog').getByRole('button', { name: '+ gpt-4o-mini' }).click();
        await shot(page, 'provider-form', theme, vp);
        await page.keyboard.press('Escape');

        if (vp === 'mobile') await page.getByRole('button', { name: 'Open menu' }).click();
        await openProfile(page);
        await shot(page, 'profile-menu', theme, vp);
        await page.getByRole('link', { name: 'My account' }).click();
        await expect(page.getByRole('heading', { name: 'My account', level: 1 })).toBeVisible();
        await shot(page, 'account', theme, vp, true);
        if (vp === 'mobile') {
          await page.getByRole('button', { name: 'Open menu' }).click();
          await shot(page, 'drawer', theme, vp);
        }
      });
    });
  }
}

test.describe('sign-in steps', () => {
  test.use({ mockOptions: { rich: true, mfa: 'enroll' } });
  for (const theme of ['light', 'dark'] as const) {
    test(`forced enrollment ${theme}`, async ({ page }) => {
      await prepare(page, theme, 'desktop');
      await page.goto('/ui/');
      await page.getByLabel('Email').fill(EMAIL);
      await page.getByLabel('Password').fill(PASSWORD);
      await page.getByRole('button', { name: 'Sign in' }).click();
      await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
      await shot(page, 'login-enroll', theme, 'desktop');
      await page.getByLabel('Authentication code').fill('123456');
      await page.getByRole('button', { name: 'Turn on two-factor authentication' }).click();
      await expect(page.getByTestId('recovery-codes')).toBeVisible();
      await shot(page, 'login-recovery-codes', theme, 'desktop');
      await page.getByRole('button', { name: 'I saved them, continue' }).click();
      await chooseOrg(page);
    });
  }
});

test('invite page', async ({ page }) => {
  await prepare(page, 'light', 'desktop');
  await page.goto('/ui/invite?token=inv_demo');
  await expect(page.getByRole('heading', { name: 'Accept your invitation' })).toBeVisible();
  await shot(page, 'invite', 'light', 'desktop');
});

test.describe('2FA step', () => {
  test.use({ mockOptions: { mfa: 'totp' } });
  test('code', async ({ page }) => {
    await prepare(page, 'light', 'desktop');
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
    await shot(page, 'login-2fa', 'light', 'desktop');
  });
});
