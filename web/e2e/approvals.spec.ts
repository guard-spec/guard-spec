// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, go, login, test } from './fixtures';

test.describe('Two-person approval', () => {
  test('lists pending requests; approves another admin\'s, withdraws its own', async ({ page, mock }) => {
    await login(page);
    await go(page, 'Approvals');
    const list = page.getByTestId('approvals-list');
    await expect(list.getByRole('listitem')).toHaveCount(2);
    const other = list.getByRole('listitem').filter({ hasText: 'Disable policy “strict”' });
    await expect(other).toContainText('ops@example.com');
    const mine = list.getByRole('listitem').filter({ hasText: 'Store prompt and answer content' });
    await expect(mine).toContainText('Your own request');
    await expect(mine.getByRole('button', { name: 'Approve' })).toHaveCount(0);
    await expect(mine.getByRole('button', { name: 'Withdraw' })).toBeVisible();

    await other.getByRole('button', { name: 'Approve' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('applies as soon as you approve');
    await dialog.getByLabel('Note').fill('agreed');
    await dialog.getByRole('button', { name: 'Approve' }).click();
    await expect(page.getByText('Approved; the change is applied.')).toBeVisible();
    await expect(list.getByRole('listitem')).toHaveCount(1);
    const call = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/approvals/apr-1/approve'));
    expect(call?.body).toMatchObject({ note: 'agreed' });

    await page.getByTestId('approvals-status').selectOption('all');
    await expect(list.getByRole('listitem')).toHaveCount(3);
    await expect(list.getByRole('listitem').filter({ hasText: 'Disable policy “strict”' })).toContainText('Approved');
  });

  test("an instance administrator approves another organization's deletion", async ({ page, mock }) => {
    await login(page);
    await go(page, 'Approvals');
    const section = page.getByTestId('instance-deletions');
    await expect(section).toContainText('Delete organization Sandbox (sandbox) and everything in it');
    await expect(section).toContainText('pilot-owner@example.com');
    await section.getByRole('button', { name: 'Approve' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Sandbox (sandbox)');
    await dialog.getByRole('button', { name: 'Approve' }).click();
    await expect(page.getByText('Approved; the change is applied.')).toBeVisible();
    await expect(section).toContainText('No organization deletion is waiting.');
    expect(mock.calls.some((c) => c.method === 'POST' && c.path.endsWith('/organizations/30000000-0000-4000-8000-000000000009/approvals/apr-org-1/approve'))).toBe(true);
  });

  test('the security policy turns it on', async ({ page, mock }) => {
    await login(page);
    await go(page, 'Security');
    await page.getByLabel('Require a second admin').check();
    await page.getByLabel('Requests expire after (hours)').fill('48');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    const put = mock.calls.find((c) => c.method === 'PUT' && c.path.endsWith('/security'));
    expect(put?.body).toMatchObject({ two_person_approval: true, approval_expiry_hours: 48 });
  });
});

test.describe('Two-person approval on the Flow page', () => {
  test.use({ mockOptions: { twoPerson: true } });
  test('disabling a policy becomes a request', async ({ page, mock }) => {
    await login(page);
    await page.getByRole('checkbox', { name: 'baseline', exact: true }).uncheck();
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText(/Disabling baseline waits for another admin/)).toBeVisible();
    // Still enabled: the server kept it until an approval.
    await expect(page.getByRole('checkbox', { name: 'baseline', exact: true })).toBeChecked();
    expect(mock.calls.some((c) => c.method === 'PUT' && /\/policies\/[^/]+$/.test(c.path))).toBe(true);
    await go(page, 'Approvals');
    await expect(page.getByTestId('approvals-list').getByRole('listitem').filter({ hasText: 'Disable policy “baseline”' })).toBeVisible();
  });
});

test.describe('Deleting a policy', () => {
  test('only a disabled policy is deleted, without approval', async ({ page, mock }) => {
    await login(page);
    const del = page.getByRole('button', { name: 'Delete policy baseline' });
    await expect(del).toHaveAttribute('aria-disabled', 'true');
    // aria-disabled, not disabled: a click explains why (Playwright waits for enabled ones).
    await del.click({ force: true });
    await expect(page.getByText(/Only a disabled policy can be deleted/)).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    await page.getByRole('checkbox', { name: 'baseline', exact: true }).uncheck();
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(del).not.toHaveAttribute('aria-disabled', 'true');
    await del.click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByRole('checkbox', { name: 'baseline', exact: true })).toHaveCount(0);
    expect(mock.calls.filter((c) => c.method === 'DELETE' && /\/policies\/[^/]+$/.test(c.path))).toHaveLength(1);
  });
});
