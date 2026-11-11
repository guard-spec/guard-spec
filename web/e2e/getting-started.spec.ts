// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Getting started (RF-a1dbafea U1): the checklist's real state, links to the
// page that fixes each step, the landing of a new org, and putting it away.

import { chooseOrg, expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

test.describe('a new organization', () => {
  test.use({ mockOptions: { newOrg: true } });

  test('lands on getting started until it is put away', async ({ page }) => {
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await chooseOrg(page);
    await expect(page.getByRole('heading', { name: 'Getting started', level: 1 })).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/start$/);
    await expect(page.getByTestId('start-progress')).toContainText('Required steps left: 3.');
    await expect(page.getByTestId('step-provider')).toHaveAttribute('data-state', 'todo');
    await expect(page.getByTestId('step-key')).toContainText('No active API key.');
    await expect(page.getByTestId('step-models')).toHaveAttribute('data-state', 'done');
    await expect(page.getByTestId('step-models')).toContainText('Layers running: L1, L2, L3 · gateway 0.2.1');

    // Each step links to the page that fixes it.
    await page.getByRole('link', { name: 'Set up: Create an API key' }).click();
    await expect(page.getByRole('heading', { name: 'API keys', level: 1 })).toBeVisible();
    await go(page, 'Getting started');

    // The dashboard of an unfinished org shows the setup card.
    await go(page, 'Dashboard');
    await expect(page.getByTestId('setup-card')).toContainText('Required steps left: 3.');
    await page.getByTestId('setup-card').getByRole('link', { name: 'Open getting started' }).click();
    await expect(page.getByRole('heading', { name: 'Getting started', level: 1 })).toBeVisible();

    // Put away: the dashboard again, without the card, also on the next landing.
    await page.getByRole('button', { name: 'Hide this page' }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
    await expect(page.getByTestId('setup-card')).toHaveCount(0);
    await page.goto('/ui/');
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
    await go(page, 'Getting started');
    await page.getByRole('button', { name: 'Show on sign-in again' }).click();
    await page.goto('/ui/');
    await expect(page.getByRole('heading', { name: 'Getting started', level: 1 })).toBeVisible();
  });

  test('in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await chooseOrg(page, 'Mở');
    await expect(page.getByRole('heading', { name: 'Bắt đầu', level: 1 })).toBeVisible();
    await expect(page.getByTestId('start-progress')).toContainText('Còn 3 bước bắt buộc.');
    await expect(page.getByRole('link', { name: 'Thiết lập: Tạo API key' })).toBeVisible();
  });
});

test('a set-up organization lands on the dashboard', async ({ page, mock }) => {
  await login(page, null);
  await expect(page.getByTestId('setup-card')).toHaveCount(0);
  await go(page, 'Getting started');
  await expect(page.getByTestId('start-progress')).toContainText('Protection is set up.');
  await expect(page.getByTestId('step-provider')).toHaveAttribute('data-state', 'done');
  expect(mock.calls.some((c) => c.path.endsWith('/getting-started'))).toBe(true);
});

test.describe('a gateway the control plane cannot read', () => {
  test.use({ mockOptions: { gateway: 'unreachable' } });
  test('shows on the dashboard without taking over the landing', async ({ page }) => {
    await login(page, null);
    await expect(page.getByTestId('setup-card')).toContainText('Required steps left: 1.');
    await go(page, 'Getting started');
    await expect(page.getByTestId('step-models')).toHaveAttribute('data-state', 'warn');
    await expect(page.getByTestId('step-models')).toContainText('The gateway did not answer');
  });
});
