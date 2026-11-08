// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Encrypted stored content (RF-771f82ec): with the key the control plane
// shows the plain text (the API decrypts it); without it the request details
// say the content is encrypted instead of showing nothing. Screenshots go to
// test-results/content-encryption/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD, STORED_PROMPT } from './mockApi';

const SHOTS = 'test-results/content-encryption';

const details = (page: import('@playwright/test').Page) =>
  page.getByTestId('audit-table').getByRole('row').nth(1).getByRole('button', { name: /^(Details of the request at|Chi tiết yêu cầu lúc)/ });

test.describe('stored content, opened by the control plane', () => {
  test.use({ mockOptions: { storeContent: true } });

  test('shows the decrypted content', async ({ page }) => {
    await login(page, null);
    await go(page, 'Request log');
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Stored content')).toBeVisible();
    await expect(dialog.locator('pre')).toContainText(STORED_PROMPT);
    await expect(dialog.getByText('Stored encrypted;')).toHaveCount(0);
    await page.screenshot({ path: `${SHOTS}/details-decrypted-en.png` });
  });
});

test.describe('stored content the control plane cannot open', () => {
  test.use({ mockOptions: { encryptedContent: true } });

  test('says it is encrypted (English)', async ({ page }) => {
    await login(page, null);
    await go(page, 'Request log');
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Stored content')).toBeVisible();
    await expect(dialog.getByText('Stored encrypted; this control plane cannot open it (no key, or the key was destroyed).')).toBeVisible();
    await expect(dialog.locator('pre')).toHaveCount(0);
    await page.screenshot({ path: `${SHOTS}/details-encrypted-en.png` });
  });

  test('says it is encrypted (Vietnamese)', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Nhật ký yêu cầu', exact: true }).click();
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Nội dung đã lưu')).toBeVisible();
    await expect(dialog.getByText('Đã lưu dạng mã hoá; control plane này không mở được (thiếu khoá, hoặc khoá đã bị huỷ).')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/details-encrypted-vi.png` });
  });
});
