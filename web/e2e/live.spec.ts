// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Opt-in: the UI as served by a real control plane (with the UI embedded),
// no mocks. Run with
//
//   LIVE_URL=http://localhost:8081 LIVE_EMAIL=... LIVE_PASSWORD=... \
//     npx playwright test --project=live
//
// It creates upstreams and a policy in the org it opens: use a test database.

import { expect, test } from '@playwright/test';

const url = process.env.LIVE_URL;
test.skip(!url, 'LIVE_URL is not set');
// One backend, shared state: one test at a time.
test.describe.configure({ mode: 'serial' });

test('routes a rule edited as text, simulates it and round-trips the config', async ({ page }) => {
  const violations: string[] = [];
  // CSP violations and page errors only: refused requests (the 422 of the
  // parse error below) also log errors.
  page.on('console', (m) => {
    if (m.type() === 'error' && /Content.Security.Policy|Refused to/i.test(m.text())) violations.push(m.text());
  });
  page.on('pageerror', (e) => violations.push(e.message));
  const id = Date.now().toString(36);

  await page.goto(`${url ?? ''}/ui/`);
  await page.getByLabel('Email').fill(process.env.LIVE_EMAIL ?? '');
  await page.getByLabel('Password').fill(process.env.LIVE_PASSWORD ?? '');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByTestId('my-orgs').getByRole('button').first().click();
  await expect(page.getByRole('heading', { name: 'Flow', level: 1 })).toBeVisible();

  // Two upstreams; the first becomes the org default.
  const nav = page.getByRole('navigation', { name: 'Main' });
  await nav.getByRole('link', { name: 'Upstreams' }).click();
  for (const [name, base] of [
    [`main-${id}`, 'https://api.openai.com/v1'],
    [`safe-${id}`, 'http://ollama:11434/v1'],
  ] as const) {
    await page.getByRole('button', { name: '+ New upstream' }).click();
    const d = page.getByRole('dialog');
    await d.getByLabel('Name').fill(name);
    await d.getByLabel('Base URL').fill(base);
    await d.getByLabel('API key environment variable').fill('UPSTREAM_KEY_MAIN');
    await d.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();
  }
  const defaultBefore = await page.getByLabel('Organization default').inputValue();
  await page.getByLabel('Organization default').selectOption({ label: `main-${id}` });
  await expect(page.getByText('Saved.').first()).toBeVisible();

  // A project of its own: its policies run before the org's, whatever they are.
  await nav.getByRole('link', { name: 'Projects' }).click();
  await page.getByLabel('Name').fill(`Live ${id}`);
  await page.getByLabel('Slug').fill(`live-${id}`);
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('cell', { name: `live-${id}`, exact: true })).toBeVisible();

  // A policy with a route rule written as text.
  await nav.getByRole('link', { name: 'Flow' }).click();
  await page.getByLabel('Scope').selectOption({ label: `Project: Live ${id}` });
  await page.getByRole('button', { name: '+ New policy' }).click();
  await page.getByRole('dialog').getByLabel('Policy name').fill(`live-${id}`);
  await page.getByRole('dialog').getByLabel('Applies to').selectOption({ label: `Live ${id}` });
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await page.getByRole('listitem').filter({ hasText: `live-${id}` }).getByRole('button', { name: '+ Add rule' }).click();
  await page.getByRole('button', { name: '+ Add rule' }).first().click();
  const panel = page.getByTestId('rule-panel');
  await panel.getByLabel('Name').fill(`jailbreaks-${id}`);
  await panel.getByLabel('Action').selectOption('route');
  await panel.getByLabel('Target upstream').selectOption(`safe-${id}`);
  await panel.getByRole('tab', { name: 'Text' }).click();
  await panel.getByTestId('condition-text').click();
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('Delete');
  await page.keyboard.type('scores.l2 > 0.8 && injection.category == "jailbreak"');
  await panel.getByRole('tab', { name: 'Visual' }).click();
  await expect(panel.locator('.rule')).toHaveCount(2);
  // A parse error shows at its position.
  await panel.getByRole('tab', { name: 'Text' }).click();
  await panel.getByTestId('condition-text').click();
  await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.type(' &&');
  await expect(panel.getByTestId('parse-error')).toBeVisible();
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await expect(panel.getByTestId('parse-error')).toBeHidden();

  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Policies saved.')).toBeVisible();
  await expect(page.getByTestId(`rule-node-jailbreaks-${id}`)).toContainText(`route → safe-${id}`);

  // Simulate: the saved policy routes a jailbreak to the safe upstream.
  const sim = page.getByTestId('simulator');
  for (const f of ['injection.score', 'scores.l1', 'indirect.score']) await sim.getByLabel(f, { exact: true }).fill('');
  await sim.getByLabel('scores.l2').fill('0.93');
  await sim.getByLabel('injection.category').selectOption('jailbreak');
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(page.getByTestId('sim-result')).toContainText(`safe-${id}`);
  await expect(page.locator('.react-flow__node.hl-match')).toContainText(`jailbreaks-${id}`);
  await sim.getByLabel('scores.l2').fill('0.1');
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(page.getByTestId('sim-result')).toContainText(`main-${id}`);

  // Config as code: the file round-trips without changes.
  await nav.getByRole('link', { name: 'Config as code' }).click();
  // CodeMirror renders only the visible lines; the round trip is the check.
  await expect(page.getByTestId('config-yaml')).toContainText('version: 1');
  await page.getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByTestId('config-result')).toContainText('No changes');

  await nav.getByRole('link', { name: 'Audit log' }).click();
  await expect(page.getByTestId('audit-table')).toBeVisible();

  // Clean up: the policy, then the upstreams (the default first, or the
  // control plane refuses to delete it).
  await nav.getByRole('link', { name: 'Flow' }).click();
  await page.getByLabel('Scope').selectOption({ label: `Project: Live ${id}` });
  await page.getByRole('button', { name: `Delete policy live-${id}` }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByTestId(`rule-node-jailbreaks-${id}`)).toBeHidden();
  await nav.getByRole('link', { name: 'Upstreams' }).click();
  await page.getByLabel('Organization default').selectOption(defaultBefore);
  await expect(page.getByLabel('Organization default')).toHaveValue(defaultBefore);
  for (const name of [`main-${id}`, `safe-${id}`]) {
    await page.getByRole('button', { name: `Delete ${name}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByRole('cell', { name, exact: true })).toBeHidden();
  }
  expect(violations).toEqual([]);
});

// Screenshots against the real control plane: LIVE_SCREENSHOTS=<dir>. Expects
// an org like the one the mocked tests use (upstreams main, safe-model and
// eu-sandbox; the baseline policy).
test('screenshots against the real control plane', async ({ page }) => {
  const dir = process.env.LIVE_SCREENSHOTS;
  test.skip(!dir, 'LIVE_SCREENSHOTS is not set');
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' && /Content.Security.Policy|Refused to/i.test(m.text())) problems.push(m.text());
  });
  page.on('pageerror', (e) => problems.push(e.message));
  const shot = async (name: string) => {
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${dir ?? ''}/live-${name}.png` });
  };

  await page.goto(`${url ?? ''}/ui/`);
  await page.getByLabel('Email').fill(process.env.LIVE_EMAIL ?? '');
  await page.getByLabel('Password').fill(process.env.LIVE_PASSWORD ?? '');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByTestId('my-orgs').getByRole('button').first().click();
  await expect(page.getByRole('heading', { name: 'Flow', level: 1 })).toBeVisible();

  const sim = page.getByTestId('simulator');
  await sim.getByLabel('scores.l2').fill('0.3');
  await sim.getByLabel('injection.score').fill('0.72');
  await sim.getByLabel('indirect.score').fill('0.6');
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(page.getByTestId('sim-result')).toContainText('safe-model');
  await shot('flow-simulator');

  await page.getByRole('button', { name: 'Edit high l2' }).click();
  const panel = page.getByTestId('rule-panel');
  await expect(panel.locator('.rule')).toHaveCount(2);
  await shot('rule-visual');
  await panel.getByRole('tab', { name: 'Text' }).click();
  await expect(panel.getByTestId('condition-text')).toContainText('scores.l2 > 0.9');
  await shot('rule-text');

  const nav = page.getByRole('navigation', { name: 'Main' });
  await nav.getByRole('link', { name: 'Upstreams' }).click();
  await expect(page.getByRole('cell', { name: 'eu-sandbox', exact: true })).toBeVisible();
  await shot('upstreams');

  await nav.getByRole('link', { name: 'Config as code' }).click();
  const editor = page.getByTestId('config-yaml');
  await expect(editor).toContainText('default_upstream: main');
  await editor.getByText('default_upstream: main').click();
  await page.keyboard.press('End');
  for (let i = 0; i < 4; i++) await page.keyboard.press('Backspace');
  await page.keyboard.type('safe-model');
  await page.getByRole('button', { name: 'Show diff' }).click();
  await page.getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByTestId('change-list')).toBeVisible();
  await shot('config');

  await nav.getByRole('link', { name: 'Audit log' }).click();
  await expect(page.getByTestId('audit-table').getByRole('cell', { name: 'safe-model' }).first()).toBeVisible();
  await shot('audit');
  expect(problems).toEqual([]);
});
