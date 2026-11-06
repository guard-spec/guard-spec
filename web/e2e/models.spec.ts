// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The Models page: the gateway's running classifier (GET /gateway/models) and
// the shadow comparison of the org (GET /shadow, /shadow/disagreements).

import { expect, login, test } from './fixtures';

const SUMMARY = /\/v1\/organizations\/[^/]+\/shadow(\?|$)/;

test.describe('Models', () => {
  test('shows the running model, the update banner and the shadow comparison', async ({ page }) => {
    await login(page, 'Models');
    const gw = page.getByTestId('gateway-models');
    await expect(gw).toContainText('guardspec-classifier@v3b');
    await expect(gw).toContainText('Verified');
    await expect(page.getByTestId('models-update')).toHaveText(
      'A new model version is available: guardspec-classifier@v3c (running guardspec-classifier@v3b). Pull it, then reload the gateway (SIGHUP or POST /admin/models/reload).',
    );
    await expect(page.getByTestId('installed-models')).toContainText('guardspec-classifier@v2');

    const tiles = page.getByTestId('shadow-tiles');
    await expect(tiles).toContainText('Compared680');
    await expect(tiles).toContainText('Agreement99.4%');
    await expect(tiles).toContainText('Shadow would block3');
    await expect(tiles).toContainText('Shadow would allow1');
    await expect(tiles).toContainText('Not compared14');
    await expect(tiles).toContainText('timeout 9 · skipped 4 · error 1');
    await expect(page.getByTestId('shadow-pairs')).toContainText('guardspec-classifier@v2');
    await expect(page.getByTestId('shadow-scores').getByRole('row', { name: /Mean/ })).toContainText('0.164');
    await expect(page.getByTestId('shadow-delta')).toContainText('+0.007');
    await expect(page.getByTestId('shadow-histogram').getByRole('row')).toHaveCount(11);
    await expect(page.getByTestId('shadow-histogram').getByRole('row', { name: /^0\.0–0\.1/ })).toContainText('412');

    await expect(page.getByTestId('disagreements-table').getByRole('row')).toHaveCount(5);

    // Another window reloads the summary.
    const week = page.waitForRequest((r) => SUMMARY.test(r.url()) && r.url().includes('window=7d'));
    await page.getByRole('button', { name: '7d' }).click();
    await week;
    await expect(page.getByTestId('shadow-tiles')).toContainText('Compared4,080');
  });

  test('filters disagreements by direction', async ({ page }) => {
    await login(page, 'Models');
    const table = page.getByTestId('disagreements-table');
    await expect(table.getByRole('row')).toHaveCount(5);
    const req = page.waitForRequest((r) => r.url().includes('/shadow/disagreements') && r.url().includes('direction=would_allow'));
    await page.getByLabel('Direction').selectOption('would_allow');
    expect(new URL((await req).url()).searchParams.get('window')).toBe('24h');
    await expect(table.getByRole('row')).toHaveCount(2);
    await expect(table).toContainText('Would allow');
    await expect(table).not.toContainText('Would block');
    await page.getByLabel('Direction').selectOption('would_block');
    await expect(table.getByRole('row')).toHaveCount(4);
  });

  test('reports a summary that fails to load', async ({ page }) => {
    await page.route(SUMMARY, (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'shadow store unavailable' }) }));
    await login(page, 'Models');
    await expect(page.getByRole('alert').filter({ hasText: 'shadow store unavailable' })).toBeVisible();
    await expect(page.getByTestId('shadow-tiles')).toHaveCount(0);
    // The running model still shows.
    await expect(page.getByTestId('models-update')).toBeVisible();
  });
});

test.describe('Models without shadow results', () => {
  test.use({ mockOptions: { noShadow: true } });
  test('shows the empty state', async ({ page }) => {
    await login(page, 'Models');
    await expect(page.getByText('No shadow results in this window. Set SHADOW_L2_MODEL on the gateway to compare a candidate model.')).toBeVisible();
    await expect(page.getByTestId('shadow-tiles')).toHaveCount(0);
    await expect(page.getByTestId('disagreements-table')).toHaveCount(0);
  });
});

test.describe('Models without a gateway', () => {
  test.use({ mockOptions: { gateway: 'unconfigured' } });
  test('asks for GATEWAY_URL', async ({ page }) => {
    await login(page, 'Models');
    await expect(page.getByTestId('gateway-not-configured')).toHaveText('Set GATEWAY_URL on the control plane to see the gateway’s models.');
    await expect(page.getByTestId('models-update')).toHaveCount(0);
  });
});

test.describe('Models with an unreachable gateway', () => {
  test.use({ mockOptions: { gateway: 'unreachable' } });
  test('shows the error', async ({ page }) => {
    await login(page, 'Models');
    await expect(page.getByTestId('gateway-models').getByRole('alert')).toContainText('The gateway did not answer: dial tcp 10.0.0.5:8080: connect: connection refused');
  });
});

test.describe('Models as a viewer', () => {
  test.use({ mockOptions: { role: 'viewer' } });
  test('shows the comparison but not the disagreements', async ({ page, mock }) => {
    await login(page, 'Models');
    await expect(page.getByTestId('shadow-tiles')).toContainText('Compared680');
    await expect(page.getByTestId('disagreements-admins-only')).toBeVisible();
    await expect(page.getByTestId('disagreements-table')).toHaveCount(0);
    expect(mock.calls.some((c) => c.path.endsWith('/shadow/disagreements'))).toBe(false);
  });
});

test('Models in Vietnamese', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
  await page.goto('/ui/');
  await page.getByLabel('Email').fill('admin@example.com');
  await page.getByLabel('Mật khẩu').fill('correct-horse-battery');
  await page.getByRole('button', { name: 'Đăng nhập' }).click();
  await page.getByTestId('my-orgs').getByRole('button').first().click();
  await expect(page.getByRole('heading', { name: 'Bảng điều khiển', level: 1 })).toBeVisible();
  await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Mô hình', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Mô hình', level: 1 })).toBeVisible();
  await expect(page.getByTestId('models-update')).toContainText('Đã có phiên bản mô hình mới: guardspec-classifier@v3c');
  await expect(page.getByTestId('shadow-tiles')).toContainText('99,4%');
});
