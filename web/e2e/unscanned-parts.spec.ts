// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Unscanned files and images (RF-c18516ae): the Guard settings select, the
// request log's tags and refusal reason, and rules on input.unscanned.* in
// the Policy flow and the Simulator. Screenshots go to
// test-results/unscanned-parts/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD, type MockState } from './mockApi';

const SHOTS = 'test-results/unscanned-parts';

/** Tags the first rows as the gateway would, and adds an unscanned_content refusal on top. */
function tagRows(mock: MockState): void {
  const [first, second] = mock.requests;
  if (!first || !second) throw new Error('seed has requests');
  first.pii_entities = ['input:unscanned_image=2'];
  second.pii_entities = ['input:pii_email=1', 'input:unscanned_file=1', 'input:server_state=1'];
  mock.requests.unshift({
    ...first,
    id: '20000000-0000-4000-8000-000000000001',
    action: 'block',
    rule_id: null,
    route_target: null,
    injection_label: null,
    injection_score: 0,
    latency_ms: 3,
    pii_entities: ['input:unscanned_audio=1'],
    created_at: new Date(Date.parse(first.created_at) + 60_000).toISOString(),
  });
}

test.describe('Unscanned files and images', () => {
  test('the Guard settings select defaults to the gateway, explains each mode and saves', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const select = page.getByLabel('Unscanned files and images');
    await expect(select).toHaveValue('');
    await expect(select.locator('option:checked')).toHaveText('Gateway default (log, unless the operator changed UNSCANNED_PARTS)');
    const group = page.getByRole('group', { name: 'Files and images' });
    await group.scrollIntoViewIfNeeded();
    await expect(group).toContainText('can only make the gateway stricter');
    await expect(group).toContainText('extract its text in your application');
    await expect(page.getByTestId('unscanned-mode-help')).toContainText('Gateway default: log');

    await select.selectOption('allow');
    await expect(page.getByTestId('unscanned-mode-help')).toContainText('takes effect only when the gateway is set to allow too');
    await select.selectOption('block');
    await expect(page.getByTestId('unscanned-mode-help')).toContainText('unscanned_content');
    await page.screenshot({ path: `${SHOTS}/guard-settings-block-en.png` });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.guard).toMatchObject({ unscanned_parts: 'block' });

    // Back to the default: the field is left out.
    await select.selectOption('');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => 'unscanned_parts' in (mock.guard as object)).toBe(false);
  });

  test('the select in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập bảo vệ', exact: true }).click();
    const select = page.getByLabel('Tệp và hình ảnh không quét được');
    await expect(select).toBeVisible();
    await select.selectOption('log');
    await page.getByRole('group', { name: 'Tệp và hình ảnh' }).scrollIntoViewIfNeeded();
    await expect(page.getByTestId('unscanned-mode-help')).toContainText('Hình ảnh không quét ×1');
    await expect(page.getByText('trích văn bản ngay trong ứng dụng')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/guard-settings-vi.png` });
  });

  test('the request log shows unscanned tags and the unscanned_content reason', async ({ page, mock }) => {
    tagRows(mock);
    await login(page, null);
    await go(page, 'Request log');
    const table = page.getByTestId('audit-table');
    await expect(table.getByTestId('unscanned-tag')).toHaveText(['Unscanned audio ×1', 'Unscanned image ×2', 'Unscanned file ×1']);
    await expect(table.getByRole('row').nth(1)).toContainText('unscanned_content');
    await page.screenshot({ path: `${SHOTS}/request-log-en.png` });

    // The refusal: a readable reason and its tag.
    await table.getByRole('row').nth(1).getByRole('button', { name: /^Details of the request/ }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByTestId('block-reason')).toContainText('Unscanned content: the request carried images, files or audio');
    await expect(dialog.getByTestId('audit-tags')).toHaveText('Unscanned audio ×1');
    await page.screenshot({ path: `${SHOTS}/request-detail-blocked-en.png` });
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    // A forwarded row: no reason, every tag, the unknown one as written.
    await table.getByRole('row').nth(3).getByRole('button', { name: /^Details of the request/ }).click();
    await expect(dialog.getByTestId('block-reason')).toHaveCount(0);
    const tags = dialog.getByTestId('audit-tags');
    await expect(tags).toContainText('Personal data: E-mail ×1');
    await expect(tags).toContainText('Unscanned file ×1');
    await expect(tags).toContainText('input:server_state=1');
    await page.screenshot({ path: `${SHOTS}/request-detail-tags-en.png` });
  });

  test('a rule on input.unscanned.kinds and input.unscanned.count, simulated', async ({ page, mock }) => {
    await login(page);
    await page.getByRole('button', { name: '+ Add rule' }).first().click();
    const panel = page.getByTestId('rule-panel');
    await panel.getByLabel('Name').fill('block files');
    await panel.getByLabel('Action', { exact: true }).selectOption('block');

    // The field picker has an Unscanned parts group: input.unscanned.* and input.pdf.*.
    await panel.getByRole('button', { name: /^Field / }).first().click();
    const list = panel.getByRole('listbox');
    const group = list.getByRole('group', { name: 'Unscanned parts' });
    await expect(group).toBeVisible();
    await expect(group.getByRole('option')).toHaveCount(5);
    await panel.getByRole('combobox', { name: 'Search fields' }).fill('audio');
    await expect(list.getByRole('option')).toHaveCount(1);
    await page.screenshot({ path: `${SHOTS}/field-picker-en.png` });
    await page.keyboard.press('Enter');
    await expect(panel.getByRole('button', { name: 'Field input.unscanned.kinds' })).toBeVisible();
    await panel.locator('.rule-value').first().selectOption('file');
    await expect(page.getByTestId('condition-problems')).toHaveCount(0);
    await expect(page.getByTestId('rule-node-block files')).toContainText('"file" in input.unscanned.kinds');

    // Its help: description, values, example.
    await panel.getByTestId('help-input.unscanned.kinds').first().hover();
    const tip = page.getByRole('tooltip').filter({ hasText: 'forwards but cannot read' });
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('image, file, audio and other');
    await page.mouse.move(0, 0);

    // The Simulator takes both fields and runs the unsaved rule.
    const sim = page.getByTestId('simulator');
    await sim.getByRole('button', { name: 'Clear' }).click();
    await sim.getByLabel('input.unscanned.kinds', { exact: true }).fill('image, file');
    await sim.getByLabel('input.unscanned.count', { exact: true }).fill('2');
    await sim.getByRole('button', { name: 'Simulate' }).click();
    const result = page.getByTestId('sim-result');
    await expect(result).toContainText('block');
    await expect(result.locator('.trace li.trace-hit')).toContainText('block files');
    const call = mock.calls.filter((c) => c.path.endsWith('/policies/simulate')).pop();
    expect((call?.body as { vars: Record<string, unknown> }).vars).toMatchObject({
      'input.unscanned.kinds': ['image', 'file'],
      'input.unscanned.count': 2,
    });
    await result.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/simulator-en.png` });

    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const put = mock.calls.filter((c) => c.method === 'PUT' && c.path.includes('/policies/')).pop();
    const rules = (put?.body as { rules: { name: string; condition: unknown }[] }).rules;
    expect(JSON.stringify(rules.find((r) => r.name === 'block files')?.condition)).toContain('"field":"input.unscanned.kinds"');
  });
});
