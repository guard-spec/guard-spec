// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The security overview, the command palette, saved filters and the CSV
// export of the request log (RF-a1dbafea U4).

import { readFile } from 'node:fs/promises';
import { expect, go, login, test } from './fixtures';

test('the security overview: trend, most attacked keys and projects, model health, versions', async ({ page }) => {
  await login(page, 'Security overview');
  await expect(page.getByTestId('sec-blocked')).toHaveText('2');
  await expect(page.getByTestId('attack-trend')).toHaveAttribute('aria-label', 'Refused requests over time, 2 in the last 24 hours');
  await expect(page.getByTestId('sec-keys')).toContainText('gs_3fa9c1d2');
  await expect(page.getByTestId('sec-keys')).toContainText('billing prod');
  await expect(page.getByTestId('sec-keys')).toContainText('1 refused of');
  await expect(page.getByTestId('sec-projects')).toContainText('1 refused of');
  await expect(page.getByTestId('model-health')).toContainText('All layers running');
  await expect(page.getByTestId('model-health')).toContainText('L1, L2, L3');
  await expect(page.getByTestId('sec-versions')).toContainText('0.2.1');

  await page.getByRole('group', { name: 'Period' }).getByRole('button', { name: '30d' }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CSV' }).click();
  expect((await download).suggestedFilename()).toMatch(/^guard-spec-acme-30d-/);
});

test.describe('a gateway that does not answer', () => {
  test.use({ mockOptions: { gateway: 'unreachable' } });
  test('says the models cannot be read', async ({ page }) => {
    await login(page, 'Security overview');
    await expect(page.getByTestId('model-health')).toContainText('Cannot read the gateway');
  });
});

test('the command palette opens with Ctrl+K and goes to pages and objects by keyboard', async ({ page }) => {
  await login(page, null);
  await page.keyboard.press('Control+k');
  const palette = page.getByRole('dialog', { name: 'Go to' });
  const box = palette.getByRole('combobox');
  await expect(box).toBeFocused();
  await box.fill('request');
  await expect(palette.getByRole('option').first()).toContainText('Request log');
  await expect(box).toHaveAttribute('aria-activedescendant', /.+/);
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Request log', level: 1 })).toBeVisible();
  await expect(palette).toBeHidden();

  // An object: a policy opens in the flow.
  await page.getByRole('button', { name: 'Search' }).click();
  await box.fill('baseline');
  await expect(palette.getByRole('option', { name: /baseline/ })).toContainText('Policy');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Policy flow', level: 1 })).toBeVisible();

  // Arrows move, Escape closes and gives focus back.
  await page.keyboard.press('Control+k');
  await box.fill('key');
  await page.keyboard.press('ArrowDown');
  await expect(palette.getByRole('option', { selected: true })).toHaveCount(1);
  await page.keyboard.press('Escape');
  await expect(palette).toBeHidden();
  await page.keyboard.press('Control+k');
  await box.fill('zzzz');
  await expect(palette.getByRole('status').first()).toContainText('Nothing matches "zzzz".');
});

test('saved filters and the CSV export of the request log', async ({ page, mock }) => {
  await login(page, null);
  await go(page, 'Request log');
  await expect(page.getByRole('button', { name: 'Save filter' })).toBeDisabled();
  await page.getByLabel('Filter by action').selectOption('block');
  await page.getByRole('button', { name: 'Save filter' }).click();
  const dialog = page.getByRole('dialog', { name: 'Save this filter' });
  await dialog.getByLabel('Name').fill('Refused');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByLabel('Saved filter', { exact: true })).toHaveValue('Refused');
  await page.getByLabel('Saved filter', { exact: true }).selectOption('');
  await expect(page.getByLabel('Filter by action')).toHaveValue('');
  // Kept across visits (this browser).
  await page.reload();
  await page.getByLabel('Saved filter', { exact: true }).selectOption('Refused');
  await expect(page.getByLabel('Filter by action')).toHaveValue('block');
  await page.getByRole('button', { name: 'Delete the saved filter Refused' }).click();
  await expect(page.getByLabel('Saved filter', { exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: 'Download CSV' }).click();
  const csv = page.getByRole('dialog', { name: 'Download the request log as CSV' });
  await csv.getByRole('radio', { name: '7 days' }).check();
  const download = page.waitForEvent('download');
  await csv.getByRole('button', { name: 'Download' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^guard-spec-acme-7d-/);
  expect((await readFile(await file.path(), 'utf8')).split('\n')[0]).toBe('period_start,period_end,section,key,requests,blocked');
  expect(mock.calls.some((c) => c.path.endsWith('/reports/requests.csv'))).toBe(true);
});
