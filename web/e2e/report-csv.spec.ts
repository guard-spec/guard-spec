// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { expect, login, test } from './fixtures';

test.describe('CSV report', () => {
  test('downloads the request log of the dashboard window as CSV', async ({ page, mock }) => {
    await login(page, 'Dashboard');
    await page.getByRole('group', { name: 'Period' }).getByRole('button', { name: '7d' }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download CSV' }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^guard-spec-acme-7d-\d{4}-\d{2}-\d{2}\.csv$/);
    const text = await (await import('node:fs/promises')).readFile(await file.path(), 'utf8');
    expect(text.split('\n')[0]).toBe('period_start,period_end,section,key,requests,blocked');
    const call = mock.calls.find((c) => c.path.endsWith('/reports/requests.csv'));
    expect(call?.method).toBe('GET');
  });
});
