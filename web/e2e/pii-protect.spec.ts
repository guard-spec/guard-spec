// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Keeping personal data from the upstream (RF-5b9b3aa2): the Guard settings
// choice of off, tokenize or redact, and the kinds to replace. Screenshots go
// to test-results/pii-protect/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/pii-protect';

test.describe('Personal data kept from the upstream', () => {
  test('tokenize with chosen kinds, saved, then back to off', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const action = page.getByLabel('Before the request goes upstream');
    await expect(action).toHaveValue('off');
    await expect(page.getByTestId('pii-action-help')).toHaveText('The model provider receives the personal data the client sent.');
    await expect(page.getByRole('group', { name: 'Kinds to replace' })).toHaveCount(0);

    await action.selectOption('tokenize');
    await expect(page.getByTestId('pii-action-help')).toContainText('⟦EMAIL_1⟧');
    const kinds = page.getByRole('group', { name: 'Kinds to replace' });
    for (const k of ['E-mail', 'Phone (VN)', 'Payment card', 'CCCD', 'IPv4']) {
      await expect(kinds.getByRole('checkbox', { name: k })).toBeChecked();
    }
    await kinds.getByRole('checkbox', { name: 'IPv4' }).uncheck();
    await page.getByRole('group', { name: 'Personal data in requests' }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/guard-settings-tokenize-en.png` });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.guard).toMatchObject({ input_pii_action: 'tokenize', input_pii_kinds: ['email', 'phone', 'card', 'cccd'] });

    // The last kind cannot be unchecked: off is the action.
    for (const k of ['E-mail', 'Phone (VN)', 'Payment card']) await kinds.getByRole('checkbox', { name: k }).uncheck();
    await kinds.getByRole('checkbox', { name: 'CCCD' }).click();
    await expect(kinds.getByRole('checkbox', { name: 'CCCD' })).toBeChecked();

    await action.selectOption('off');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => (mock.guard as { input_pii_action?: string }).input_pii_action).toBeUndefined();
  });

  test('redact, in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập bảo vệ', exact: true }).click();
    await page.getByLabel('Trước khi gửi request lên upstream').selectOption('tokenize');
    await expect(page.getByTestId('pii-action-help')).toContainText('Câu trả lời, streaming hay không, được trả lại giá trị');
    await page.getByRole('group', { name: 'Dữ liệu cá nhân trong request' }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/guard-settings-tokenize-vi.png` });
    await page.getByLabel('Trước khi gửi request lên upstream').selectOption('redact');
    await expect(page.getByTestId('pii-action-help')).toContainText('[EMAIL]');
    await page.screenshot({ path: `${SHOTS}/guard-settings-redact-vi.png` });
  });
});
