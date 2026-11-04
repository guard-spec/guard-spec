// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// README screenshots, taken against the mocked API: npm run screenshots
// (writes docs/images/admin-*.png).

import type { Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { chooseOrg, expect, login, test } from './fixtures';

const OUT = fileURLToPath(new URL('../../docs/images/', import.meta.url));

async function shot(page: Page, name: string) {
  await page.waitForTimeout(400); // fitView and CodeMirror settle
  await page.screenshot({ path: `${OUT}admin-${name}.png`, animations: 'disabled' });
}

async function setTheme(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript((t) => localStorage.setItem('gs.theme', t), theme);
}

test('login', async ({ page }) => {
  await setTheme(page, 'light');
  await page.goto('/ui/');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await shot(page, 'login');
});

test('flow with a simulated request', async ({ page }) => {
  await setTheme(page, 'light');
  await login(page);
  const sim = page.getByTestId('simulator');
  await sim.getByLabel('scores.l2').fill('0.3');
  await sim.getByLabel('injection.score').fill('0.72');
  await sim.getByLabel('indirect.score').fill('0.6');
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(page.getByTestId('sim-result')).toContainText('safe-model');
  await shot(page, 'flow');
});

test('rule editor, visual and text', async ({ page }) => {
  await setTheme(page, 'light');
  await login(page);
  await page.getByRole('button', { name: 'Edit high l2' }).click();
  await expect(page.getByTestId('rule-panel').locator('.rule')).toHaveCount(2);
  await shot(page, 'rule-visual');
  await page.getByTestId('rule-panel').getByRole('tab', { name: 'Text' }).click();
  await expect(page.getByTestId('condition-text')).toContainText('scores.l2 > 0.9');
  await shot(page, 'rule-text');
});

test('flow, dark theme, Vietnamese', async ({ page }) => {
  await setTheme(page, 'dark');
  await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
  await page.goto('/ui/');
  await page.getByLabel('Email').fill('admin@example.com');
  await page.getByLabel('Mật khẩu').fill('correct-horse-battery');
  await page.getByRole('button', { name: 'Đăng nhập' }).click();
  await chooseOrg(page, 'Mở');
  await expect(page.getByRole('heading', { name: 'Bảng điều khiển', level: 1 })).toBeVisible();
  await page.getByRole('link', { name: 'Luồng chính sách' }).click();
  await expect(page.getByRole('heading', { name: 'Luồng chính sách', level: 1 })).toBeVisible();
  await page.getByLabel('Phạm vi').selectOption({ label: 'Dự án: Billing bot' });
  await shot(page, 'flow-dark-vi');
});

test('upstreams', async ({ page }) => {
  await setTheme(page, 'light');
  await login(page);
  await page.getByRole('link', { name: 'Model providers' }).click();
  await expect(page.getByTestId('providers-table').getByText('safe-model', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Edit provider main' }).click();
  await shot(page, 'upstreams');
});

test('config as code', async ({ page }) => {
  await setTheme(page, 'light');
  await login(page);
  await page.getByRole('link', { name: 'Config as code' }).click();
  const editor = page.getByTestId('config-yaml');
  await expect(editor).toContainText('default_upstream: main');
  await editor.getByText('default_upstream: main').click();
  await page.keyboard.press('End');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.type('safe-model');
  await page.getByRole('button', { name: 'Show diff' }).click();
  await page.getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByTestId('change-list')).toBeVisible();
  await shot(page, 'config');
});

test('api keys and audit log', async ({ page }) => {
  await setTheme(page, 'light');
  await login(page);
  await page.getByRole('link', { name: 'Request log' }).click();
  await expect(page.getByTestId('audit-table').getByRole('row')).toHaveCount(7);
  await shot(page, 'audit');
  await page.getByRole('link', { name: 'Guard settings' }).click();
  await expect(page.getByLabel('Spotlight')).toHaveValue('delimit');
  await shot(page, 'guard');
});
