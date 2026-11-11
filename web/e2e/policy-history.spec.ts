// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, go, login, test } from './fixtures';

test.describe('Policy history', () => {
  test('lists versions, shows the diff and rolls back', async ({ page, mock }) => {
    await login(page);
    await go(page, 'Policy history');
    const versions = page.getByTestId('history-versions');
    await expect(versions.getByRole('button')).toHaveCount(3);
    await expect(versions.getByRole('button').first()).toContainText('v3');
    await expect(versions.getByRole('button').first()).toContainText('current');
    // v3 against v2: the route rule was added.
    const diff = page.getByTestId('history-diff');
    await expect(diff).toContainText('Changes from v2 to v3');
    await expect(diff).toContainText('added');
    await expect(diff).toContainText('suspicious to safe model');

    // The first version on its own.
    await versions.getByRole('button', { name: /v1/ }).click();
    await expect(page.getByTestId('history-rules')).toContainText('high l2');
    await page.getByRole('button', { name: 'Roll back to v1' }).click();
    await page.getByRole('dialog').getByLabel('Reason').fill('too noisy');
    await page.getByRole('dialog').getByRole('button', { name: 'Roll back' }).click();
    await expect(versions.getByRole('button')).toHaveCount(4);
    await expect(versions.getByRole('button').first()).toContainText('rollback to v1');
    await expect(versions.getByRole('button').first()).toContainText('too noisy');
    const call = mock.calls.find((c) => c.method === 'POST' && /\/policies\/[^/]+\/rollback$/.test(c.path));
    expect(call?.body).toMatchObject({ version: 1, reason: 'too noisy' });
  });

  test('log-only is saved from the Flow page', async ({ page, mock }) => {
    await login(page);
    await page.getByLabel('Log only baseline').check();
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const call = mock.calls.find((c) => c.method === 'PUT' && /\/policies\/[^/]+$/.test(c.path));
    expect(call?.body).toMatchObject({ log_only: true });
  });
});

test.describe('Policy history as a viewer', () => {
  test.use({ mockOptions: { role: 'viewer' } });
  test('shows the versions without a rollback button', async ({ page }) => {
    await login(page);
    await go(page, 'Policy history');
    await expect(page.getByTestId('history-versions').getByRole('button')).toHaveCount(3);
    await page.getByTestId('history-versions').getByRole('button', { name: /v1/ }).click();
    await expect(page.getByRole('button', { name: /Roll back/ })).toHaveCount(0);
  });
});
