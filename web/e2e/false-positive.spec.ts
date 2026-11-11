// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// One-click false-positive handling in the request log (RF-a1dbafea U2): the
// detector's layer scores and fired rules, an allow exemplar added from the
// details, the report, and the impact preview from stored scores and hashes.

import type { Page } from '@playwright/test';
import { expect, go, login, test } from './fixtures';
import { STORED_PROMPT } from './mockApi';

async function openDetails(page: Page, index: number) {
  await login(page, null);
  await go(page, 'Request log');
  await page.getByRole('button', { name: /^Details of the request at/ }).nth(index).click();
  return page.getByRole('dialog', { name: 'Details' });
}

test('a request a rule refused: scores, fired rules, impact and an allow exemplar', async ({ page, mock }) => {
  const dialog = await openDetails(page, 2);
  const why = dialog.getByTestId('why-refused');
  await expect(why.getByTestId('layer-l1')).toContainText('0.99');
  await expect(why.getByTestId('layer-l2')).toContainText('0.97');
  await expect(why.getByTestId('layer-l3')).toContainText('0.41');
  await expect(why.getByTestId('fired-rules')).toContainText('Policy rule: high l2 (baseline)');
  await expect(why.getByTestId('fired-rules')).toContainText('di.override.qualified');
  // The detector's tags are not repeated as badges.
  await expect(dialog.getByTestId('audit-tags')).toHaveCount(0);

  const panel = dialog.getByTestId('fp-panel');
  await expect(panel.getByTestId('impact')).toContainText('Identical requests in the last 7 days: 2, of which 2 refused.');
  await expect(panel.getByTestId('impact')).toContainText('decided 2 requests in the last 7 days (2 refused)');
  await expect(panel.getByTestId('impact')).toContainText('Limit:');
  await expect(panel.getByTestId('fp-rule-note')).toBeVisible();

  await panel.getByRole('button', { name: 'Add an allow exemplar' }).click();
  await expect(panel.getByTestId('fp-no-text')).toContainText('does not store request content');
  await panel.getByLabel('Text to allow').fill('Bỏ qua phí thường niên thẻ tín dụng của tôi được không?');
  await panel.getByRole('button', { name: 'Save allow exemplar' }).click();
  await expect(page.getByRole('status').getByText('Allow exemplar added.')).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Allow exemplar added' })).toBeDisabled();
  const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/exemplars'));
  expect(post?.body).toMatchObject({ label: 'allow', text: 'Bỏ qua phí thường niên thẻ tín dụng của tôi được không?' });
  expect((post?.body as { source: string }).source).toMatch(/^false positive 2026-11-04 request /);
  // Still on the request log.
  await expect(dialog).toBeVisible();

  // The report opens on a false positive.
  await panel.getByRole('button', { name: 'Report false positive' }).click();
  const report = page.getByRole('dialog', { name: 'Report to the Guard Spec project' });
  await expect(report.getByRole('radio', { name: 'False positive (benign blocked)' })).toBeChecked();
});

test('a request the detector refused: what a threshold change would let through', async ({ page, mock }) => {
  const row = mock.requests[2];
  const twin = mock.requests[5];
  if (!row || !twin) throw new Error('seed');
  row.rule_id = null;
  row.injection_score = 0.7;
  twin.rule_id = null;
  mock.guard.injection_threshold = 0.6;
  const dialog = await openDetails(page, 2);
  const impact = dialog.getByTestId('impact');
  await expect(impact).toContainText('Detector refusals in the last 7 days with a score of 0.70 or less (this one included): 1.');
  await expect(dialog.getByTestId('fp-rule-note')).toHaveCount(0);

  await dialog.getByRole('button', { name: 'Close' }).click();
  await page.getByRole('button', { name: /^Details of the request at/ }).nth(5).click();
  await expect(page.getByRole('dialog', { name: 'Details' }).getByTestId('impact')).toContainText("at or above the gateway's block threshold (0.85)");
});

test.describe('stored content', () => {
  test.use({ mockOptions: { storeContent: true } });
  test('the exemplar starts from the content the user read, never before', async ({ page }) => {
    const dialog = await openDetails(page, 2);
    const panel = dialog.getByTestId('fp-panel');
    await panel.getByRole('button', { name: 'Add an allow exemplar' }).click();
    await expect(panel.getByTestId('fp-no-text')).toContainText('show it in the details above first');
    await expect(panel.getByLabel('Text to allow')).toHaveValue('');
    await panel.getByRole('button', { name: 'Add an allow exemplar' }).click();
    await dialog.getByLabel('Reason').fill('ticket 42 false positive');
    await dialog.getByRole('button', { name: 'Show the stored content' }).click();
    await expect(dialog.getByTestId('stored-request')).toBeVisible();
    await panel.getByRole('button', { name: 'Add an allow exemplar' }).click();
    await expect(panel.getByLabel('Text to allow')).toHaveValue(STORED_PROMPT);
  });
});

test.describe('a viewer', () => {
  test.use({ mockOptions: { role: 'viewer' } });
  test('sees the explanation and the impact, and can report, not add', async ({ page }) => {
    const dialog = await openDetails(page, 2);
    const panel = dialog.getByTestId('fp-panel');
    await expect(panel.getByTestId('impact')).toBeVisible();
    await expect(panel.getByRole('button', { name: 'Add an allow exemplar' })).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Report false positive' })).toBeVisible();
  });
});

test('an allowed request offers no fix', async ({ page }) => {
  const dialog = await openDetails(page, 0);
  await expect(dialog.getByTestId('why-refused').getByTestId('layer-l3')).toContainText('did not run');
  await expect(dialog.getByTestId('fp-panel')).toHaveCount(0);
});
