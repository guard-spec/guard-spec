// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Per-organization input settings (RF-113cd269): the instance limits, the
// inherited behaviour, a tightening saved at once and a loosening that waits
// for a second admin. Screenshots go to test-results/input-settings/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/input-settings';

test.describe('Input settings', () => {
  test('inherits, tightens at once, checks the ceiling', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Input settings');
    const instance = page.getByTestId('input-instance');
    await expect(instance).toContainText('200000');
    await expect(instance).toContainText('log');
    await expect(page.getByRole('radio', { name: /Use the instance’s behaviour/ })).toBeChecked();

    await page.getByRole('radio', { name: 'Set them for this organization' }).check();
    await expect(page.getByRole('radio', { name: /Text only/ })).toBeChecked();
    const tokens = page.getByLabel('Most tokens per request');
    await tokens.fill('200001');
    await expect(page.getByText('A whole number from 1 to 200000, or empty.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
    await tokens.fill('8000');
    await page.screenshot({ path: `${SHOTS}/text-only-en.png`, fullPage: true });
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.input?.settings).toEqual({ input_mode: 'text_only', max_input_tokens: 8000, allowed_file_types: [], unreadable_file_action: 'block' });
  });

  test.describe('with two-person approval', () => {
    test.use({ mockOptions: { twoPerson: true } });

    test('a loosening waits for a second admin', async ({ page, mock }) => {
      mock.input = { settings: { input_mode: 'text_only', max_input_tokens: 8000, allowed_file_types: [], unreadable_file_action: 'block' }, updated_at: null };
      await login(page, null);
      await go(page, 'Input settings');
      await page.getByRole('radio', { name: /Text and allowed files/ }).check();
      await page.getByRole('checkbox', { name: /PDF documents/ }).check();
      await page.getByLabel('A file the gateway cannot read').selectOption('pass');
      const notice = page.getByTestId('input-loosens');
      await expect(notice).toContainText('files accepted, a file type added, unreadable files forwarded');
      await expect(notice).toContainText('waits for a second admin');
      await page.getByLabel('Reason for the second admin').fill('contracts arrive as PDFs');
      await page.getByRole('button', { name: 'Request approval' }).click();
      await expect(page.getByText('The change waits for a second admin.')).toBeVisible();
      await expect(page.getByTestId('input-pending')).toContainText('files accepted, a file type added, unreadable files forwarded');
      await page.screenshot({ path: `${SHOTS}/pending-en.png`, fullPage: true });
      // Nothing changed yet; the request is listed for the other admins.
      expect(mock.input).toMatchObject({ settings: { input_mode: 'text_only' } });
      const req = mock.identity.approvals.find((a) => a.kind === 'input_settings.loosen');
      expect(req).toMatchObject({ status: 'pending', reason: 'contracts arrive as PDFs' });
      await page.getByTestId('input-pending').getByRole('link', { name: 'Open approvals' }).click();
      await expect(page.getByText('Loosen the input settings')).toBeVisible();
    });
  });

  test('the page in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập đầu vào', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Thiết lập đầu vào', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Giới hạn của instance' })).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/input-vi.png`, fullPage: true });
  });
});
