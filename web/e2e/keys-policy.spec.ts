// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, go, login, test } from './fixtures';

test.describe('API key policy', () => {
  test('creates a key limited to addresses and rotates one', async ({ page, mock }) => {
    await login(page);
    await go(page, 'API keys');
    await expect(page.getByRole('cell', { name: '1 networks' })).toBeVisible();

    await page.getByRole('button', { name: 'New API key' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Alias').fill('edge');
    await dialog.getByLabel('Allowed addresses').fill('203.0.113.0/24');
    await dialog.getByLabel('Allowed addresses').press('Enter');
    await dialog.getByLabel('Allowed addresses').fill('not an address');
    await dialog.getByLabel('Allowed addresses').press('Enter');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog.getByRole('alert')).toContainText('not an address');
    await dialog.getByRole('button', { name: /Remove not an address/ }).click();
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByTestId('new-key-secret')).toHaveText(/^gs_[0-9a-f]{32}$/);
    const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/api-keys'));
    expect(post?.body).toMatchObject({ alias: 'edge', allowed_cidrs: ['203.0.113.0/24'] });
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();

    await page.getByRole('button', { name: 'Rotate gs_8b20e4aa' }).click();
    await page.getByRole('dialog').getByLabel('Overlap (hours)').fill('2');
    await page.getByRole('dialog').getByRole('button', { name: 'Rotate' }).click();
    await expect(page.getByRole('dialog')).toContainText('The old key gs_8b20e4aa… works until');
    await expect(page.getByTestId('new-key-secret')).toHaveText(/^gs_[0-9a-f]{32}$/);
    const rotate = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/api-keys/gs_8b20e4aa/rotate'));
    expect(rotate?.body).toMatchObject({ overlap_hours: 2 });
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();
    await expect(page.getByRole('row', { name: /gs_8b20e4aa/ })).toContainText('Rotated');
    await expect(page.getByRole('button', { name: 'Rotate gs_8b20e4aa' })).toHaveCount(0);
  });

  test('the security policy caps key lifetimes', async ({ page, mock }) => {
    await login(page);
    await go(page, 'Security');
    await page.getByLabel('Keys expire within (days)').fill('90');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    const put = mock.calls.find((c) => c.method === 'PUT' && c.path.endsWith('/security'));
    expect(put?.body).toMatchObject({ api_key_max_lifetime_days: 90 });
    await go(page, 'API keys');
    await expect(page.getByText('expire within 90 days')).toBeVisible();
    await page.getByRole('button', { name: 'New API key' }).click();
    await expect(page.getByRole('dialog').getByLabel('Expires')).not.toHaveValue('');
  });
});
