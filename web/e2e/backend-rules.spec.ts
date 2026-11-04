// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Control-plane rules added with routing (#21): config export problems,
// unique policy names, the UPSTREAM_KEY_ORGS allowlist.

import { expect, login, test } from './fixtures';

test.describe('config export problems', () => {
  test.use({ mockOptions: { exportProblems: true } });

  test('lists the policies to fix and links to the rule', async ({ page }) => {
    await login(page);
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Config as code' }).click();
    const list = page.getByTestId('export-problems');
    await expect(list).toContainText('field was removed');
    await expect(list).toContainText('replace the rule with PUT');
    await list.getByRole('link', { name: 'Policy baseline · high l2' }).click();
    await expect(page.getByRole('heading', { name: 'Flow', level: 1 })).toBeVisible();
    await expect(page.getByTestId('rule-panel')).toContainText('Rule: high l2');
    await expect(page).not.toHaveURL(/policy=/);
  });
});

test('refuses a duplicate policy name and renames a policy', async ({ page, mock }) => {
  await login(page);
  await page.getByRole('button', { name: '+ New policy' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Policy name').fill('baseline');
  await expect(dialog.getByText('Another policy of this organization has this name.')).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Create' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('button', { name: 'Rename policy baseline' }).click();
  await page.getByRole('dialog').getByLabel('Policy name').fill('org baseline');
  await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Policies saved.')).toBeVisible();
  expect(mock.policies.map((p) => p.name)).toContain('org baseline');
});

test('shows a refused key variable at the field, with the operator setting', async ({ page }) => {
  await login(page);
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Upstreams' }).click();
  await page.getByRole('button', { name: '+ New upstream' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('UPSTREAM_KEY_MAIN=*;UPSTREAM_KEY_X=<org-id>')).toBeVisible();
  await expect(dialog.getByText(/UPSTREAM_ALLOW_PRIVATE=true/)).toBeVisible();
  await dialog.getByLabel('Name').fill('other');
  await dialog.getByLabel('Base URL').fill('https://other.example.com/v1');
  await dialog.getByLabel('API key environment variable').fill('UPSTREAM_KEY_FORBIDDEN');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.locator('.field-error')).toContainText('is not allowed for this organization');
  await expect(dialog.getByLabel('API key environment variable')).toHaveAttribute('aria-invalid', 'true');
  await dialog.getByLabel('API key environment variable').fill('UPSTREAM_KEY_MAIN');
  await expect(dialog.locator('.field-error')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('cell', { name: 'other', exact: true })).toBeVisible();
});
