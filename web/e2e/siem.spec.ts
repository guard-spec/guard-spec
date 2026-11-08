// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// SIEM export (RF-f2f95010): an admin adds a Splunk sink with a SIEM_*
// variable, sends a test event, sees a failing one, deletes it; viewers do
// not see the page. Screenshots go to test-results/siem/.

import { expect, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/siem';

async function openSiem(page: import('@playwright/test').Page) {
  await login(page, null);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'SIEM export', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'SIEM export', level: 1 })).toBeVisible();
}

test('adds a Splunk sink, tests it, deletes it', async ({ page, mock }) => {
  await openSiem(page);
  await expect(page.getByTestId('siem-empty')).toBeVisible();
  await page.getByRole('button', { name: 'Add a sink' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Add a sink' });
  await dialog.getByLabel('Name').fill('SOC Splunk');
  await expect(dialog.getByLabel('Destination')).toHaveValue('splunk_hec');
  await expect(dialog.getByText('the secret is the HEC token')).toBeVisible();
  // A variable the operator did not grant is refused, with the reason.
  await dialog.getByLabel('URL *').fill('https://splunk.acme.example:8088');
  await dialog.getByLabel('Index').fill('security');
  await dialog.getByLabel('Secret variable').fill('SPLUNK_TOKEN');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByRole('alert')).toContainText('ALERTS_SECRET_ORGS');
  await dialog.getByLabel('Secret variable').fill('SIEM_SPLUNK_TOKEN');
  await dialog.getByLabel('Event types').fill('detection., security.');
  await dialog.getByLabel('Lowest severity').selectOption('warning');
  await page.screenshot({ path: `${SHOTS}/add-splunk-en.png` });
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByTestId('siem-table')).toContainText('SOC Splunk');
  expect(mock.siemSinks?.[0]).toMatchObject({ kind: 'splunk_hec', config: { url: 'https://splunk.acme.example:8088', index: 'security' },
    secret_env: 'SIEM_SPLUNK_TOKEN', event_types: ['detection.', 'security.'], min_severity: 'warning' });
  await page.getByRole('button', { name: 'Send test' }).click();
  await expect(page.getByText('Test event sent to SOC Splunk.')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/list-en.png` });

  await page.getByRole('button', { name: 'Delete' }).click();
  await page.getByRole('dialog', { name: 'Delete sink' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByTestId('siem-empty')).toBeVisible();
});

test.describe('a viewer', () => {
  test.use({ mockOptions: { role: 'viewer' } });
  test('has no SIEM page', async ({ page }) => {
    await login(page, null);
    await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'SIEM export' })).toHaveCount(0);
  });
});

test('in Vietnamese', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
  await page.goto('/ui/');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Mật khẩu').fill(PASSWORD);
  await page.getByRole('button', { name: 'Đăng nhập' }).click();
  await page.getByTestId('my-orgs').getByRole('button').first().click();
  await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Xuất sang SIEM', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Xuất sự kiện sang SIEM', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: 'Thêm đích' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Thêm đích' });
  await dialog.getByLabel('Đích').selectOption('sentinel');
  await expect(dialog.getByText('Logs Ingestion API')).toBeVisible();
  await page.screenshot({ path: `${SHOTS}/add-sentinel-vi.png` });
});
