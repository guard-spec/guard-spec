// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// UI polish found by a screenshot run against a real backend (RF-N16):
// layout at common widths, readable names instead of ids, locale dates.

import type { Page } from '@playwright/test';
import { expect, go, login, openProfile, test } from './fixtures';

test.use({ mockOptions: { rich: true } });

/**
 * Tables that scroll sideways or come within HEADROOM px of it (font metrics
 * differ between systems), or a page wider than the viewport.
 */
const HEADROOM = 32;
async function overflows(page: Page): Promise<string[]> {
  return page.evaluate((headroom) => {
    const out: string[] = [];
    document.querySelectorAll<HTMLElement>('.table-wrap').forEach((el) => {
      const table = el.querySelector('table');
      const name = table?.dataset.testid ?? '?';
      if (el.scrollWidth > el.clientWidth + 1) out.push(`table ${name}: ${el.scrollWidth} > ${el.clientWidth}`);
      if (table) {
        // The narrowest the table can get, without the 100% stretch.
        const before = table.style.width;
        table.style.width = 'min-content';
        const min = table.offsetWidth;
        table.style.width = before;
        if (min > el.clientWidth - headroom) out.push(`table ${name}: needs ${min}px of ${el.clientWidth}px (headroom ${headroom}px)`);
      }
    });
    if (document.documentElement.scrollWidth > window.innerWidth + 1) out.push(`page: ${document.documentElement.scrollWidth} > ${window.innerWidth}`);
    return out;
  }, HEADROOM);
}

const PAGES = ['Model providers', 'Request log', 'Activity log', 'Members', 'API keys', 'Exemplars', 'Projects', 'Users', 'Identity providers', 'Instance activity'];

for (const width of [1280, 1440]) {
  test(`every table fits at ${width}px`, async ({ page }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width, height: 900 });
    await login(page, null);
    const found: string[] = [];
    for (const name of PAGES) {
      await go(page, name);
      await page.locator('.skeleton').first().waitFor({ state: 'detached' }).catch(() => undefined);
      await page.waitForTimeout(150);
      found.push(...(await overflows(page)).map((o) => `${name}: ${o}`));
    }
    await go(page, 'Model providers');
    await page.getByRole('button', { name: 'Test connection of main' }).click();
    await expect(page.getByTestId('test-result')).toBeVisible();
    found.push(...(await overflows(page)).map((o) => `providers with a test result: ${o}`));
    expect(found).toEqual([]);
  });
}

test('providers: icon actions, ellipsis with a title, the test result under the row', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page, 'Model providers');
  const table = page.getByTestId('providers-table');
  const long = table.getByText('azure-eastasia-production-gpt4o', { exact: true });
  await expect(long).toHaveAttribute('title', 'azure-eastasia-production-gpt4o');
  expect(await long.evaluate((el) => getComputedStyle(el).whiteSpace)).toBe('nowrap');
  await expect(page.getByRole('button', { name: 'Edit provider azure-eastasia-production-gpt4o' })).toBeInViewport();
  await page.getByRole('button', { name: 'Test connection of main' }).click();
  const result = page.getByTestId('test-result');
  await expect(result).toContainText('Connection test of main');
  await expect(result).toContainText('212 ms');
  // In its own row: the main row keeps its height.
  const row = table.getByRole('row').filter({ hasText: 'https://api.openai.com/v1' }).first();
  expect((await row.boundingBox())?.height ?? 999).toBeLessThan(80);
  await result.getByRole('button', { name: 'Dismiss' }).click();
  await expect(result).toBeHidden();
});

test('members show provider names for sign-in methods, never oidc:<id>', async ({ page }) => {
  await login(page, 'Members');
  const table = page.getByTestId('members-table');
  await expect(table).toContainText('Okta');
  await expect(table).toContainText('SSO');
  await expect(table).not.toContainText('oidc:');
});

test('dashboard and request log compare labels in any case and show decisions alike', async ({ page }) => {
  await login(page, null);
  await expect(page.getByTestId('dash-range')).toBeVisible();
  const top = page.getByTestId('dash-labels');
  await expect(top).toContainText('jailbreak');
  await expect(top).not.toContainText(/benign/i);
  const transforms = await page.locator('.meter-list .action').evaluateAll((els) => els.map((e) => getComputedStyle(e).textTransform));
  expect(new Set(transforms)).toEqual(new Set(['uppercase']));
  await go(page, 'Request log');
  await expect(page.getByTestId('audit-table')).not.toContainText('BENIGN');
  // Rule names, not ids.
  await page.getByLabel('Filter by action').selectOption('route');
  await expect(page.getByTestId('audit-table')).toContainText('suspicious to safe model');
});

test('dashboard reads server aggregates by window and project', async ({ page, mock }) => {
  const calls: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes('/dashboard')) calls.push(new URL(r.url()).search);
  });
  await login(page, null);
  await expect(page.getByTestId('dash-range')).toContainText('24 hours, by hour');
  // All 420 seeded requests fall in the last day; none is read by the browser.
  await expect(page.locator('.tile-value').first()).toHaveText('420');
  // Rules by name and policy, not id.
  await expect(page.getByTestId('dash-rules')).toContainText('high l2 · baseline');
  await expect(page.getByTestId('dash-projects')).toContainText(mock.projects[0]?.name ?? 'missing');
  await expect(page.getByTestId('dash-projects')).toContainText('No project');

  await page.getByRole('group', { name: 'Period' }).getByRole('button', { name: '7d' }).click();
  await expect(page.getByTestId('dash-range')).toContainText('7 days, by day');
  await page.getByLabel('Project', { exact: true }).selectOption({ label: mock.projects[0]?.name ?? '' });
  await expect(page.locator('.tile-value').first()).toHaveText('210');
  expect(calls).toContain(`?window=7d&project_id=${mock.projects[0]?.id}`);
});

test('activity shows the email of a user target', async ({ page, mock }) => {
  await login(page, 'Activity log');
  const labelled = mock.identity.activity.find((a) => a.target_label);
  await expect(page.getByTestId('activity-table')).toContainText(labelled?.target_label ?? 'missing');
  await expect(page.getByTestId('activity-table').getByText(labelled?.target ?? 'x', { exact: true })).toHaveCount(0);
});

test('profile menu fits in the viewport, above the sidebar', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await login(page, null);
  await openProfile(page);
  const panel = page.getByRole('group', { name: 'Profile menu' });
  await expect(panel.getByLabel('Language')).toBeInViewport({ ratio: 1 });
  await expect(panel.getByRole('button', { name: 'Theme: System' })).toBeInViewport({ ratio: 1 });
  const box = await panel.boundingBox();
  expect(box && box.x + box.width <= 1280 && box.y >= 0).toBe(true);
  await page.keyboard.press('Escape');
  await expect(panel).toBeHidden();
});

test('instance admin pages are reachable at 900px height and in the drawer', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page, null);
  const nav = page.getByRole('navigation', { name: 'Main' });
  const users = nav.getByRole('link', { name: 'Users', exact: true });
  await users.scrollIntoViewIfNeeded();
  await expect(users).toBeInViewport();
  // The profile stays pinned while the nav scrolls.
  await expect(page.getByRole('button', { name: /^Profile menu/ })).toBeInViewport();
  await page.setViewportSize({ width: 390, height: 700 });
  await page.getByRole('button', { name: 'Open menu' }).click();
  const instance = nav.getByRole('link', { name: 'Instance activity' });
  await instance.scrollIntoViewIfNeeded();
  await expect(instance).toBeInViewport();
  await instance.click();
  await expect(page.getByRole('heading', { name: 'Instance activity', level: 1 })).toBeVisible();
});

test('my account: aligned password fields, device names, Vietnamese dates', async ({ page }) => {
  await login(page, null);
  await openProfile(page);
  await page.getByRole('link', { name: 'My account' }).click();
  const a = await page.getByLabel('New password', { exact: true }).boundingBox();
  const b = await page.getByLabel('Confirm new password').boundingBox();
  expect(Math.abs((a?.y ?? 0) - (b?.y ?? 100))).toBeLessThan(2);
  const sessions = page.getByTestId('sessions-table');
  await expect(sessions).toContainText('Chrome on macOS');
  await expect(sessions).toContainText('API client');
  await openProfile(page);
  await page.getByLabel('Language').selectOption('vi');
  await page.keyboard.press('Escape');
  // vi-VN: "thg" for the month, no AM/PM.
  await expect(sessions).toContainText(/thg|trước/);
  await expect(sessions).not.toContainText(/\b(AM|PM)\b/);
});

test('2FA enroll: full-width code input and unbroken secret groups', async ({ page }) => {
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  const { installMockApi, seedState } = await import('./mockApi');
  await installMockApi(page, seedState(), { mfa: 'enroll' });
  await page.goto('/ui/');
  await page.getByLabel('Email').fill('admin@example.com');
  await page.getByLabel('Password').fill('correct-horse-battery');
  await page.getByRole('button', { name: 'Sign in' }).click();
  const input = page.getByLabel('Authentication code');
  const button = page.getByRole('button', { name: 'Turn on two-factor authentication' });
  expect(Math.abs(((await input.boundingBox())?.width ?? 0) - ((await button.boundingBox())?.width ?? 1))).toBeLessThan(2);
  const groups = await page.locator('.secret-group').evaluateAll((els) => els.map((e) => (e as HTMLElement).getClientRects().length));
  expect(groups.every((n) => n === 1)).toBe(true);
});
