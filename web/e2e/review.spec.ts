// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Review follow-ups: the org list, unsaved-changes guard, Save waiting for
// the condition text, recent orgs cleared on logout.

import { EMAIL, PASSWORD } from './mockApi';
import { expect, login, logout, test } from './fixtures';

test('lists the organizations of the user, with the role', async ({ page }) => {
  await page.goto('/ui/');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  const list = page.getByTestId('my-orgs');
  await expect(list.getByRole('button')).toHaveCount(1);
  await expect(list).toContainText('Acme Corp');
  await expect(list).toContainText('Owner');
  // Opening by id stays available.
  await expect(page.getByLabel('Organization id')).toBeVisible();
  await list.getByRole('button', { name: /Acme Corp/ }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
});

test('asks before leaving the Flow page with unsaved changes', async ({ page }) => {
  await login(page);
  const nav = page.getByRole('navigation', { name: 'Main' });
  // Without edits, nothing is asked.
  await nav.getByRole('link', { name: 'Request log' }).click();
  await expect(page.getByRole('heading', { name: 'Request log', level: 1 })).toBeVisible();
  await nav.getByRole('link', { name: 'Policy flow' }).click();

  await page.getByRole('button', { name: 'Move tag characters up' }).click();
  await nav.getByRole('link', { name: 'Model providers' }).click();
  const dialog = page.getByRole('dialog', { name: 'Leave with unsaved changes?' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'Policy flow', level: 1 })).toBeVisible();
  await expect(page.locator('.badge-warn', { hasText: 'unsaved' })).toBeVisible();

  // The browser's back button is held too.
  await page.goBack();
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL(/\/ui\/flow$/);
  await dialog.getByRole('button', { name: 'Cancel' }).click();

  await nav.getByRole('link', { name: 'Model providers' }).click();
  await dialog.getByRole('button', { name: 'Discard and leave' }).click();
  await expect(page.getByRole('heading', { name: 'Model providers', level: 1 })).toBeVisible();
});

test('Save waits until the condition text parses', async ({ page, mock }) => {
  await login(page);
  await page.getByRole('button', { name: 'Edit high l2' }).click();
  const panel = page.getByTestId('rule-panel');
  await panel.getByLabel('Name').fill('renamed');
  const save = page.getByRole('button', { name: 'Save changes' });
  await expect(save).toBeEnabled();
  await panel.getByRole('tab', { name: 'Text' }).click();
  await panel.getByTestId('condition-text').click();
  await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.type(' &&');
  await expect(panel.getByTestId('parse-error')).toBeVisible();
  await expect(save).toBeDisabled();
  await expect(page.getByText('Fix the condition text to save')).toBeVisible();
  for (let i = 0; i < 3; i++) await page.keyboard.press('Backspace');
  await expect(panel.getByTestId('parse-error')).toBeHidden();
  await expect(save).toBeEnabled();
  await save.click();
  await expect(page.getByText('Policies saved.')).toBeVisible();
  expect(mock.calls.filter((c) => c.method === 'PUT' && c.path.includes('/policies/'))).toHaveLength(1);
});

test('creates a new policy disabled in one request', async ({ page, mock }) => {
  await login(page);
  await page.getByRole('button', { name: '+ New policy' }).click();
  await page.getByRole('dialog').getByLabel('Policy name').fill('later');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  const row = page.getByRole('listitem').filter({ hasText: 'later' });
  await row.getByRole('checkbox', { name: 'later', exact: true }).uncheck();
  await row.getByRole('button', { name: '+ Add rule' }).click();
  await page.getByRole('button', { name: '+ Add rule' }).first().click();
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Policies saved.')).toBeVisible();
  const posts = mock.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/policies'));
  expect(posts).toHaveLength(1);
  expect(posts[0]?.body).toMatchObject({ name: 'later', enabled: false });
  expect(mock.calls.filter((c) => c.method === 'PUT' && c.path.includes('/policies/'))).toHaveLength(0);
  expect(mock.policies.find((p) => p.name === 'later')?.enabled).toBe(false);
});

test('Escape still closes a dialog', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: '+ New policy' }).click();
  await expect(page.getByRole('dialog', { name: 'New policy' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'New policy' })).toBeHidden();
});

test('forgets recent organizations on logout', async ({ page }) => {
  await login(page);
  expect(await page.evaluate(() => localStorage.getItem('gs.recentOrgs'))).toContain('Acme Corp');
  await logout(page);
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('gs.recentOrgs'))).toBeNull();
});
