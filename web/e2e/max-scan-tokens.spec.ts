// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Large inputs (RF-320915ea): the org's max_scan_tokens on the Guard settings
// page. Screenshots go to test-results/max-scan-tokens/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/max-scan-tokens';

test.describe('Most tokens scanned per request', () => {
  test('defaults to the gateway, refuses a bad value and saves', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const field = page.getByLabel('Most tokens scanned per request');
    await expect(field).toHaveValue('');
    await expect(field).toHaveAttribute('placeholder', /MAX_SCAN_TOKENS/);
    const group = page.getByRole('group', { name: 'Large inputs' });
    await group.scrollIntoViewIfNeeded();
    await expect(group).toContainText("can only lower the gateway's MAX_SCAN_TOKENS");

    await field.fill('0');
    await expect(group).toContainText('A whole number from 1 to 10000000.');
    await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();

    await field.fill('20000');
    await page.screenshot({ path: `${SHOTS}/guard-settings-en.png` });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.guard).toMatchObject({ max_scan_tokens: 20000 });

    // Cleared: the field is left out, the gateway's cap applies.
    await field.fill('');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => 'max_scan_tokens' in (mock.guard as object)).toBe(false);
  });

  test('the field in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập bảo vệ', exact: true }).click();
    const field = page.getByLabel('Số token tối đa được quét cho mỗi request');
    await expect(field).toBeVisible();
    await page.getByRole('group', { name: 'Input lớn' }).scrollIntoViewIfNeeded();
    await expect(page.getByText('chỉ có thể hạ MAX_SCAN_TOKENS')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/guard-settings-vi.png` });
  });
});
