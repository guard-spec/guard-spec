// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The Flow page's node panels, help tips, field picker, templates and inline
// validation (RF-8c813bc5).

import type { Page } from '@playwright/test';
import { expect, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const PANELS: { testId: string; panel: string; heading: RegExp }[] = [
  { testId: 'step-node-request', panel: 'node-panel-request', heading: /^Request/ },
  { testId: 'step-node-key', panel: 'node-panel-key', heading: /^API key and scope/ },
  { testId: 'step-node-sanitizer', panel: 'node-panel-sanitizer', heading: /^L0 sanitizer/ },
  { testId: 'detectors-node', panel: 'node-panel-detectors', heading: /^Detectors/ },
  { testId: 'terminal-block', panel: 'node-panel-block', heading: /^Block/ },
  { testId: 'terminal-log', panel: 'node-panel-log', heading: /^Log/ },
  { testId: 'terminal-allow', panel: 'node-panel-allow', heading: /^Allow/ },
  { testId: 'upstream-node-safe-model', panel: 'node-panel-upstream', heading: /^Upstream safe-model/ },
  { testId: 'step-node-output', panel: 'node-panel-output', heading: /^Output guard/ },
  { testId: 'step-node-client', panel: 'node-panel-client', heading: /^Client/ },
];

async function loginVi(page: Page) {
  await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
  await page.goto('/ui/');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Mật khẩu').fill(PASSWORD);
  await page.getByRole('button', { name: 'Đăng nhập' }).click();
  await page.getByTestId('my-orgs').getByRole('button').first().click();
  await expect(page.getByRole('heading', { name: 'Bảng điều khiển', level: 1 })).toBeVisible();
  await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Luồng chính sách', exact: true }).click();
}

test.describe('Flow page node panels', () => {
  test('every node opens a panel on the same page, even with unsaved edits', async ({ page }) => {
    await login(page);
    // An unsaved rule edit: opening a panel must not ask to leave.
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    await page.getByTestId('rule-panel').getByLabel('Name', { exact: true }).fill('high l2 edited');
    const url = page.url();
    for (const p of PANELS) {
      await page.getByTestId(p.testId).click();
      const panel = page.getByTestId(p.panel);
      await expect(panel).toBeVisible();
      await expect(panel.getByRole('heading', { level: 2 })).toHaveText(p.heading);
      await expect(panel.getByTestId('open-settings')).toBeVisible();
      await expect(page.getByText('Leave with unsaved changes?')).toHaveCount(0);
      expect(page.url()).toBe(url);
    }
    await expect(page.locator('.badge-warn', { hasText: '1 unsaved' })).toBeVisible();
    // The rule panel comes back from the rule list.
    await page.getByRole('button', { name: 'Edit high l2 edited' }).click();
    await expect(page.getByTestId('rule-panel')).toBeVisible();
  });

  test('a node opens with the keyboard too', async ({ page }) => {
    await login(page);
    await page.getByTestId('terminal-block').locator('xpath=..').focus();
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('node-panel-block')).toBeVisible();
  });

  test('the upstream panel shows the model allowlist and the rules routing to it', async ({ page, mock }) => {
    const safe = mock.upstreams.find((u) => u.name === 'safe-model');
    if (safe) safe.models = ['qwen3:4b', 'qwen3:8b'];
    await login(page);
    await page.getByTestId('upstream-node-safe-model').click();
    const panel = page.getByTestId('node-panel-upstream');
    await expect(panel.getByTestId('upstream-models')).toContainText('qwen3:8b');
    await expect(panel.getByRole('button', { name: 'suspicious to safe model' })).toBeVisible();
    await expect(panel).toContainText('edited on the Model providers page');
    await panel.getByRole('button', { name: 'suspicious to safe model' }).click();
    await expect(page.getByTestId('rule-panel')).toBeVisible();
  });

  test('edits a detector threshold, a scan setting and a rule, and saves them once', async ({ page, mock }) => {
    await login(page);
    await page.getByTestId('detectors-node').click();
    const det = page.getByTestId('node-panel-detectors');
    await expect(det.getByTestId('active-model')).toContainText('guardspec-classifier@v3b');
    // The L1 floor is the gateway's (FUSION_L1_FLOOR), shown read-only.
    await expect(det.getByTestId('l1-floor')).toHaveText('0.985');
    await expect(det.getByRole('textbox', { name: 'L1 floor' })).toHaveCount(0);
    const threshold = det.getByRole('textbox', { name: 'Block at injection score' });
    await threshold.fill('0.95');
    await expect(det.getByRole('alert')).toContainText('at most 0.85');
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    await threshold.fill('0.7');
    await expect(page.getByTestId('detectors-node')).toContainText('blocks at 0.7');

    await page.getByTestId('step-node-sanitizer').click();
    await page.getByTestId('node-panel-sanitizer').getByLabel('Spotlight', { exact: true }).selectOption('datamark');

    await page.getByRole('button', { name: 'Edit high l2' }).click();
    await page.getByTestId('rule-panel').getByLabel('Name', { exact: true }).fill('very high l2');
    await expect(page.locator('.badge-warn', { hasText: '2 unsaved' })).toBeVisible();

    const before = mock.calls.length;
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Changes saved.')).toBeVisible();
    const writes = mock.calls.slice(before).filter((c) => c.method === 'PUT');
    // Guard settings first, then the policy.
    expect(writes.map((c) => c.path.replace(/[0-9a-f-]{36}/g, ':id'))).toEqual(['/organizations/:id/guard-settings', '/organizations/:id/policies/:id']);
    expect(mock.guard).toEqual({ scan_roles: { system: true }, spotlight: 'datamark', injection_threshold: 0.7 });
    await expect(page.locator('.badge-warn', { hasText: 'unsaved' })).toHaveCount(0);
  });

  test('reports a guard settings failure and still saves the rules', async ({ page, mock }) => {
    await login(page);
    await page.route('**/v1/organizations/*/guard-settings', (route) =>
      route.request().method() === 'PUT'
        ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'database unavailable' }) })
        : route.fallback(),
    );
    await page.getByTestId('detectors-node').click();
    await page.getByRole('textbox', { name: 'Block at indirect score' }).fill('0.6');
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    await page.getByTestId('rule-panel').getByLabel('Name', { exact: true }).fill('renamed');
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Guard settings were not saved: database unavailable' })).toBeVisible();
    await expect(page.getByRole('alert').filter({ hasText: 'Some changes were saved' })).toBeVisible();
    expect(mock.policies.some((p) => p.rules.some((r) => r.name === 'renamed'))).toBe(true);
    // The guard edit is kept for another try.
    await expect(page.locator('.badge-warn', { hasText: '1 unsaved' })).toBeVisible();
    await page.getByRole('button', { name: 'Discard' }).click();
    await expect(page.locator('.badge-warn', { hasText: 'unsaved' })).toHaveCount(0);
  });

});

test.describe('Flow page for a viewer', () => {
  test.use({ mockOptions: { role: 'viewer' } });
  test('a viewer sees why the panels are read-only', async ({ page }) => {
    await login(page);
    await expect(page.getByTestId('policies-readonly')).toBeVisible();
    await page.getByTestId('step-node-sanitizer').click();
    await expect(page.getByTestId('guard-readonly')).toContainText('org.settings.write');
    await expect(page.getByTestId('node-panel-sanitizer').getByLabel('Spotlight', { exact: true })).toBeDisabled();
  });
});

test.describe('Flow page help', () => {
  test('a help tip shows on hover and on keyboard focus', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    const tip = page.getByTestId('rule-panel').getByTestId('help-scores.l2').first();
    const id = await tip.getAttribute('aria-describedby');
    expect(id).toBeTruthy();
    const pop = page.locator(`[id="${id}"]`);
    await expect(pop).toBeHidden();
    await expect(pop).toHaveAttribute('role', 'tooltip');
    await tip.hover();
    await expect(pop).toBeVisible();
    await expect(pop).toContainText('-1 when L2 did not run');
    await page.mouse.move(0, 0);
    await expect(pop).toBeHidden();
    await tip.focus();
    await expect(pop).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(pop).toBeHidden();

    // Edges and node types are explained in the legend.
    const legend = page.getByTestId('flow-legend');
    await legend.getByTestId('help-edge-noMatch').focus();
    await expect(page.getByRole('tooltip').filter({ hasText: 'the next rule is checked' })).toBeVisible();
    // Simulator fields share the variable help.
    await page.getByTestId('simulator').getByTestId('help-anomaly.has_bidi').hover();
    await expect(page.getByRole('tooltip').filter({ hasText: 'bidirectional control characters' })).toBeVisible();
  });

  test('the field picker is searchable, grouped and not truncated', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await login(page);
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    for (const width of [1280, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      const value = page.getByTestId('rule-panel').locator('.field-picker-value').nth(1);
      await expect(value).toHaveText('injection.category');
      const fits = await value.evaluate((el) => el.scrollWidth <= el.clientWidth + 1);
      expect(fits, `field name fits at ${width}px`).toBe(true);
    }
    const panel = page.getByTestId('rule-panel');
    await panel.getByRole('button', { name: 'Field injection.category' }).click();
    const list = panel.getByRole('listbox');
    for (const g of ['Detection scores', 'Anomalies', 'Indirect content', 'Request', 'MCP']) {
      await expect(list.getByRole('group', { name: g })).toBeVisible();
    }
    await panel.getByRole('combobox', { name: 'Search fields' }).fill('bidi');
    await expect(list.getByRole('option')).toHaveCount(1);
    await expect(list.getByRole('option')).toContainText('bidirectional control characters');
    await page.keyboard.press('Enter');
    await expect(panel.getByRole('button', { name: 'Field anomaly.has_bidi' })).toBeVisible();
    await expect(page.getByTestId('rule-node-high l2')).toContainText('anomaly.has_bidi == true');
  });

  test('shows condition problems inline', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    const panel = page.getByTestId('rule-panel');
    const value = panel.locator('.rule-value').first();
    await value.fill('abc');
    await expect(panel.getByTestId('condition-problems')).toContainText('scores.l2 needs a number, for example 0.7');
    await expect(panel.locator('.rule.queryBuilder-invalid')).toHaveCount(1);
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    await value.fill('2');
    await expect(panel.getByTestId('condition-problems')).toContainText('scores.l2 is between -1 and 1');
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeEnabled();
  });
});

test.describe('Flow page templates', () => {
  test('an empty scope offers templates; one click adds a rule that saves', async ({ page, mock }) => {
    mock.policies = [];
    await login(page);
    const templates = page.getByTestId('templates');
    await expect(templates).toContainText('Start with a template');
    await expect(templates.getByRole('listitem')).toHaveCount(4);
    await expect(templates).toContainText('Route suspicious requests to safe-model');
    await templates.getByRole('button', { name: 'Add this rule: Block high-risk injection' }).click();
    await expect(page.getByTestId('rule-node-Block high-risk injection')).toContainText('injection.score >= 0.7 && injection.label != "BENIGN"');
    await expect(page.getByTestId('condition-problems')).toHaveCount(0);
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const post = mock.calls.find((c) => c.method === 'POST' && c.path.endsWith('/policies'));
    expect(post?.body).toMatchObject({
      name: 'default',
      rules: [
        {
          name: 'Block high-risk injection',
          action: 'block',
          condition: {
            combinator: 'and',
            rules: [
              { field: 'injection.score', operator: '>=', value: '0.7' },
              { field: 'injection.label', operator: '!=', value: 'BENIGN' },
            ],
          },
        },
      ],
    });
  });

  test('no route template without another upstream', async ({ page, mock }) => {
    mock.policies = [];
    mock.upstreams = mock.upstreams.filter((u) => u.name === 'main');
    await login(page);
    await expect(page.getByTestId('templates').getByRole('listitem')).toHaveCount(3);
    await expect(page.getByTestId('templates')).not.toContainText('Route suspicious');
  });
});

test('Flow page in Vietnamese', async ({ page, mock }) => {
  mock.policies = [];
  await loginVi(page);
  await expect(page.getByTestId('templates')).toContainText('Bắt đầu từ một mẫu');
  await expect(page.getByTestId('templates')).toContainText('Chặn injection nguy cơ cao');
  await page.getByTestId('detectors-node').click();
  const det = page.getByTestId('node-panel-detectors');
  await expect(det.getByRole('heading', { level: 2 })).toHaveText(/^Bộ phát hiện/);
  await expect(det).toContainText('Ngưỡng chặn');
  await expect(det.getByTestId('open-settings')).toHaveText('Mở trang thiết lập đầy đủ →');
  await page.getByTestId('simulator').getByTestId('help-indirect.score').hover();
  await expect(page.getByRole('tooltip').filter({ hasText: 'Điểm injection cao nhất trong nội dung từ bên thứ ba' })).toBeVisible();
  await expect(page.getByTestId('simulator')).toContainText('Nội dung gián tiếp');
});
