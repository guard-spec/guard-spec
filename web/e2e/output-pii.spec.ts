// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Personal data in responses per organization (RF-e9ac5935): the Guard
// settings choice of gateway default, redact or off, and the kinds to redact.
// Screenshots go to test-results/output-pii/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/output-pii';

test.describe('Personal data in responses', () => {
  test('gateway default, own kinds, off, then back to the default', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const group = page.getByRole('group', { name: 'Personal data in responses' });
    const action = group.getByLabel('In the answer');
    await expect(action).toHaveValue('');
    await expect(page.getByTestId('output-pii-help')).toContainText('OUTPUT_PII_REDACT');
    const kinds = page.getByRole('group', { name: 'Kinds to redact in answers' });
    for (const k of ['E-mail', 'Phone (VN)', 'Payment card', 'CCCD']) {
      await expect(kinds.getByRole('checkbox', { name: k })).toBeChecked();
    }
    await expect(kinds.getByRole('checkbox', { name: 'IPv4' })).not.toBeChecked();

    // Redact with the org's own kinds.
    await action.selectOption('redact');
    await kinds.getByRole('checkbox', { name: 'IPv4' }).check();
    await kinds.getByRole('checkbox', { name: 'Phone (VN)' }).uncheck();
    await expect(page.getByTestId('output-pii-kinds-help')).toContainText("This organization's own list");
    await group.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/guard-settings-output-pii-en.png` });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.guard).toMatchObject({ output_pii_action: 'redact', output_pii_kinds: ['email', 'card', 'cccd', 'ipv4'] });

    // Off hides the kinds and saves without them.
    await action.selectOption('off');
    await expect(kinds).toHaveCount(0);
    await expect(page.getByTestId('output-pii-help')).toContainText('tokenize');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => mock.guard as object).toMatchObject({ output_pii_action: 'off' });
    expect((mock.guard as { output_pii_kinds?: string[] }).output_pii_kinds).toBeUndefined();
    // The page takes the saved settings back before the next change.
    await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeEnabled();

    // Back to the gateway's default: nothing stored.
    await action.selectOption({ label: 'Gateway default' });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => (mock.guard as { output_pii_action?: string }).output_pii_action).toBeUndefined();
  });

  test('the kinds go back to the gateway list', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const kinds = page.getByRole('group', { name: 'Kinds to redact in answers' });
    await kinds.getByRole('checkbox', { name: 'E-mail' }).uncheck();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => mock.guard as object).toMatchObject({ output_pii_kinds: ['phone', 'card', 'cccd'] });
    await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: "Use the gateway's kinds" }).click();
    await expect(kinds.getByRole('checkbox', { name: 'E-mail' })).toBeChecked();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => (mock.guard as { output_pii_kinds?: string[] }).output_pii_kinds).toBeUndefined();
  });

  test('in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập bảo vệ', exact: true }).click();
    const group = page.getByRole('group', { name: 'Dữ liệu cá nhân trong câu trả lời' });
    await group.getByLabel('Trong câu trả lời').selectOption('off');
    await expect(page.getByTestId('output-pii-help')).toContainText('vẫn được trả lại');
    await group.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/guard-settings-output-pii-vi.png` });
  });
});
