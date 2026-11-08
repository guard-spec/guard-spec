// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Stored content in the request log (RF-771f82ec, RF-aceaddfc): the list
// never carries it; the details read it on request, with a reason, which the
// control plane logs; encrypted content the control plane cannot open says
// so. Screenshots go to test-results/content-encryption/.

import type { Page } from '@playwright/test';
import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD, STORED_PROMPT } from './mockApi';

const SHOTS = 'test-results/content-encryption';

const details = (page: Page) =>
  page.getByTestId('audit-table').getByRole('row').nth(1).getByRole('button', { name: /^(Details of the request at|Chi tiết yêu cầu lúc)/ });

test.describe('stored content, read with a reason', () => {
  test.use({ mockOptions: { storeContent: true } });

  test('needs a reason, then shows the content and logs the read', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Request log');
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Stored content', { exact: true })).toBeVisible();
    await expect(dialog.locator('pre')).toHaveCount(0);
    await expect(dialog.getByText('Reading it is recorded in the activity log, with your reason.')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/details-reason-en.png` });
    await dialog.getByRole('button', { name: 'Show the stored content' }).click();
    await expect(dialog.getByRole('alert')).toHaveText('Your organization requires a reason (at least 3 characters).');
    expect(mock.contentReads ?? []).toHaveLength(0);
    await dialog.getByLabel('Reason').fill('ticket #42');
    await dialog.getByRole('button', { name: 'Show the stored content' }).click();
    await expect(dialog.getByTestId('stored-request')).toContainText(STORED_PROMPT);
    expect(mock.contentReads).toEqual([expect.objectContaining({ reason: 'ticket #42' })]);
    await page.screenshot({ path: `${SHOTS}/details-decrypted-en.png` });
  });
});

test.describe('a role below content_read_role', () => {
  test.use({ mockOptions: { storeContent: true, role: 'viewer' } });

  test('is refused', async ({ page }) => {
    await login(page, null);
    await go(page, 'Request log');
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Reason').fill('curious');
    await dialog.getByRole('button', { name: 'Show the stored content' }).click();
    await expect(dialog.getByRole('alert')).toContainText('Your role cannot read stored content');
  });
});

test.describe('stored content the control plane cannot open', () => {
  test.use({ mockOptions: { encryptedContent: true } });

  test('says it is encrypted (English)', async ({ page }) => {
    await login(page, null);
    await go(page, 'Request log');
    await details(page).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Reason').fill('ticket #42');
    await dialog.getByRole('button', { name: 'Show the stored content' }).click();
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
    await expect(dialog.getByText('Việc xem được ghi vào nhật ký hoạt động, kèm lý do của bạn.')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/details-reason-vi.png` });
    await dialog.getByLabel('Lý do').fill('điều tra ticket #42');
    await dialog.getByRole('button', { name: 'Xem nội dung đã lưu' }).click();
    await expect(dialog.getByText('Đã lưu dạng mã hoá; control plane này không mở được (thiếu khoá, hoặc khoá đã bị huỷ).')).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/details-encrypted-vi.png` });
  });
});

test('the security policy sets who reads stored content', async ({ page, mock }) => {
  await login(page, null);
  await go(page, 'Security');
  const role = page.getByLabel('Lowest role that may read it');
  await expect(role).toHaveValue('admin');
  await role.selectOption('member');
  await page.getByRole('checkbox', { name: 'Require a reason' }).uncheck();
  await page.getByRole('group', { name: 'Stored content' }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${SHOTS}/security-content-en.png` });
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect.poll(() => mock.identity.security.content_read_role).toBe('member');
  expect(mock.identity.security.content_view_reason).toBe(false);
});
