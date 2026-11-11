// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Automated accessibility (RF-a1dbafea U5): axe-core on every page of the
// admin UI, in English and in Vietnamese, and on the new dialogs. A serious
// or critical violation of WCAG 2.1 A or AA fails the test, with the rule,
// the page and the elements in the message.

import AxeBuilder from '@axe-core/playwright';
import type { Page } from '@playwright/test';
import { PATHS } from '../src/paths';
import { expect, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const FAIL_ON = new Set(['serious', 'critical']);

/** Every page with a screen of its own; the SSO callback and login are visited separately. */
const PAGES = (Object.keys(PATHS) as (keyof typeof PATHS)[]).filter((r) => !['auth-callback', 'login', 'invite', 'orgs'].includes(r));

async function scan(page: Page, where: string): Promise<string[]> {
  const result = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  return result.violations
    .filter((v) => FAIL_ON.has(v.impact ?? ''))
    .map((v) => `${where}: ${v.id} (${v.impact}) ${v.help}\n    ${v.nodes.slice(0, 5).map((n) => `${n.target.join(' ')}: ${n.any[0]?.message ?? n.failureSummary ?? ''}`).join('\n    ')}`);
}

/** The page is drawn: its heading, and no loading placeholder. */
async function settled(page: Page) {
  await expect(page.locator('main h1').first()).toBeVisible();
  await expect(page.locator('main .loading, main [aria-busy="true"]')).toHaveCount(0);
  await page.waitForTimeout(150);
}

test.use({ mockOptions: { rich: true } });

for (const lang of ['en', 'vi'] as const) {
  test(`every page has no serious accessibility violation (${lang})`, async ({ page }) => {
    test.setTimeout(240_000);
    const found: string[] = [];
    if (lang === 'vi') await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    found.push(...(await scan(page, `${lang} login`)));
    await page.goto('/ui/invite?token=inv_demo');
    await expect(page.locator('h1, h2').first()).toBeVisible();
    found.push(...(await scan(page, `${lang} invite`)));

    if (lang === 'vi') {
      await page.goto('/ui/');
      await page.getByLabel('Email').fill(EMAIL);
      await page.getByLabel('Mật khẩu').fill(PASSWORD);
      await page.getByRole('button', { name: 'Đăng nhập' }).click();
      await page.getByTestId('my-orgs').getByRole('button').first().click();
      await expect(page.getByRole('heading', { name: 'Bảng điều khiển', level: 1 })).toBeVisible();
    } else {
      await login(page, null);
    }
    await page.goto('/ui/orgs');
    await expect(page.getByTestId('my-orgs')).toBeVisible();
    found.push(...(await scan(page, `${lang} orgs`)));

    for (const route of PAGES) {
      await page.goto(`/ui/${PATHS[route]}`);
      await settled(page);
      found.push(...(await scan(page, `${lang} ${route}`)));
    }

    // The new dialogs and panels.
    await page.goto('/ui/requests');
    await settled(page);
    await page.locator('table button').first().click();
    await page.getByRole('dialog').first().waitFor();
    found.push(...(await scan(page, `${lang} request details`)));
    await page.keyboard.press('Escape');
    await page.keyboard.press('Control+k');
    await page.getByTestId('palette').getByRole('combobox').fill('a');
    found.push(...(await scan(page, `${lang} command palette`)));

    expect(found, found.join('\n')).toEqual([]);
  });
}
