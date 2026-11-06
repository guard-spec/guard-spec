// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import type { Page } from '@playwright/test';
import { expect, login, test } from './fixtures';

// Select all, then delete before typing: typing over a selection makes
// Chrome's contenteditable copy the replaced text's computed style into a
// style attribute, which the CSP blocks (harmlessly, but it logs an error).
async function clearEditor(page: Page) {
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('Delete');
}

test.describe('Flow page', () => {
  test('shows the request path, the rules in gateway order and the terminals', async ({ page, mock }) => {
    await login(page);
    const diagram = page.getByTestId('diagram');
    for (const name of ['L0 sanitizer', 'L1 rules', 'L2 classifier', 'L3 embeddings', 'Output guard', 'Client']) {
      await expect(diagram.getByText(name, { exact: true })).toBeVisible();
    }
    await expect(diagram.getByTestId('rule-node-high l2')).toContainText('scores.l2 > 0.9 && injection.category != "benign"');
    await expect(diagram.getByTestId('rule-node-suspicious to safe model')).toContainText('route → safe-model');
    await expect(diagram.getByTestId('terminal-block')).toBeVisible();
    await expect(diagram.getByTestId('terminal-log')).toBeVisible();
    await expect(diagram.getByTestId('upstream-node-safe-model')).toBeVisible();
    // The org default upstream carries the badge.
    await expect(diagram.getByTestId('upstream-node-main')).toContainText('default');

    const list = page.getByTestId('rule-list');
    await expect(list.getByRole('listitem')).toHaveCount(4);
    // The project policy runs first for keys of that project.
    await page.getByLabel('Scope').selectOption({ label: 'Project: Billing bot' });
    await expect(list.getByRole('listitem')).toHaveCount(5);
    await expect(list.getByRole('listitem').first()).toContainText('any l1 hit');
    expect(mock.calls.some((c) => c.path === '/policy/schema')).toBe(true);
  });

  test('clicking a detector opens its panel on the same page', async ({ page }) => {
    await login(page);
    await page.getByTestId('diagram').getByText('L2 classifier', { exact: true }).click();
    await expect(page.getByTestId('node-panel-detectors')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Policy flow', level: 1 })).toBeVisible();
  });

  test('edits a rule in the visual and text tabs and saves it', async ({ page, mock }) => {
    await login(page);
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    const panel = page.getByTestId('rule-panel');
    await expect(panel).toBeVisible();
    // Opening a rule (and formatting it as text) changes nothing.
    await panel.getByRole('tab', { name: 'Text' }).click();
    await expect(panel.getByTestId('condition-text')).toContainText('scores.l2 > 0.9');
    await panel.getByRole('tab', { name: 'Visual' }).click();
    await expect(page.locator('.badge-warn', { hasText: 'unsaved' })).toHaveCount(0);
    await panel.getByLabel('Name').fill('very high l2');

    // Text tab: shows the formatted condition, parses edits back.
    await panel.getByRole('tab', { name: 'Text' }).click();
    const editor = panel.getByTestId('condition-text');
    await expect(editor).toContainText('scores.l2 > 0.9');
    await editor.click();
    await clearEditor(page);
    await page.keyboard.type('scores.l2 > 0.95 && injection.category in ["jailbreak", "exfiltration"]');
    await expect.poll(() => mock.calls.filter((c) => c.path === '/policy/parse').length).toBeGreaterThan(0);

    // The visual tab shows the parsed tree.
    await panel.getByRole('tab', { name: 'Visual' }).click();
    await expect(panel.locator('.rule')).toHaveCount(2);
    await expect(page.getByTestId('rule-node-very high l2')).toContainText('scores.l2 > 0.95');

    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const put = mock.calls.find((c) => c.method === 'PUT' && c.path.includes('/policies/'));
    const rules = (put?.body as { rules: { name: string; condition: { rules: { operator: string; value: string }[] } }[] }).rules;
    expect(rules[0]?.name).toBe('very high l2');
    expect(rules[0]?.condition.rules[1]).toMatchObject({ operator: 'in', value: ['jailbreak', 'exfiltration'] });
    // Builder ids are not stored.
    expect(JSON.stringify(rules)).not.toContain('"id":"r-');
  });

  test('shows a parse error inline at its position', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: 'Edit high l2' }).click();
    const panel = page.getByTestId('rule-panel');
    await panel.getByRole('tab', { name: 'Text' }).click();
    const editor = panel.getByTestId('condition-text');
    await editor.click();
    await clearEditor(page);
    await page.keyboard.type('scores.l2 > "high"');
    await expect(panel.getByTestId('parse-error')).toContainText('Not valid at character 12');
    await expect(panel.locator('.cm-lintRange-error')).toHaveCount(1);
  });

  test('reorders rules with the keyboard and by dragging', async ({ page, mock }) => {
    await login(page);
    const items = page.getByTestId('rule-list').getByRole('listitem');
    await page.getByRole('button', { name: 'Move tag characters up' }).click();
    await expect(items.nth(2)).toContainText('tag characters');

    // Drag "high l2" (first) below "log tool injections" in the diagram (top to bottom).
    await page.evaluate(() => window.scrollTo(0, 0));
    const first = page.getByTestId('rule-node-high l2');
    const second = page.getByTestId('rule-node-log tool injections');
    const a = await first.boundingBox();
    const b = await second.boundingBox();
    if (!a || !b) throw new Error('nodes not laid out');
    await page.mouse.move(a.x + 30, a.y + 12);
    await page.mouse.down();
    await page.mouse.move(a.x + 30, b.y + b.height + 10, { steps: 12 });
    await page.mouse.up();
    await expect(items.nth(0)).toContainText('log tool injections');
    await expect(items.nth(1)).toContainText('high l2');

    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const put = mock.calls.find((c) => c.method === 'PUT' && c.path.includes('/policies/'));
    expect((put?.body as { rules: { name: string }[] }).rules.map((r) => r.name)).toEqual([
      'log tool injections',
      'high l2',
      'tag characters',
      'suspicious to safe model',
    ]);
  });

  test('connecting a rule to an upstream makes it a route rule', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: 'Fit View' }).click();
    const node = page.getByTestId('rule-node-high l2');
    const from = await node.locator('.handle-match').boundingBox();
    const to = await page.getByTestId('upstream-node-eu-sandbox').boundingBox();
    if (!from || !to) throw new Error('nodes not laid out');
    await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2);
    await page.mouse.down();
    await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 15 });
    await page.mouse.up();
    await expect(node).toContainText('route → eu-sandbox');
    await expect(page.getByTestId('rule-panel').getByLabel('Target upstream')).toHaveValue('eu-sandbox');
  });

  test('adds and deletes a rule; shows server validation errors', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: '+ Add rule' }).first().click();
    const panel = page.getByTestId('rule-panel');
    await panel.getByLabel('Name').fill('to nowhere');
    await panel.getByLabel('Action', { exact: true }).selectOption('route');
    await expect(panel.getByLabel('Target upstream')).toHaveValue('main');
    await expect(page.getByTestId('rule-list').getByRole('listitem')).toHaveCount(5);
    await panel.getByRole('button', { name: 'Delete rule' }).click();
    await expect(page.getByTestId('rule-list').getByRole('listitem')).toHaveCount(4);

    // A rule with an empty value is caught before saving.
    await page.getByRole('button', { name: '+ Add rule' }).first().click();
    await page.getByTestId('rule-panel').getByLabel('Name').fill('bad rule');
    await page.getByTestId('rule-panel').locator('.rule-value').fill('');
    await expect(page.getByTestId('condition-problems')).toContainText('Enter a value for injection.score.');
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    await expect(page.getByText('Fix the rule conditions to save')).toBeVisible();

    // An error only the server finds is shown on the rule.
    await page.getByTestId('rule-panel').locator('.rule-value').fill('0.5');
    await page.route('**/v1/organizations/*/policies/*', (route) =>
      route.request().method() === 'PUT'
        ? route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'rule "bad rule": cost limit exceeded' }) })
        : route.fallback(),
    );
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Policy baseline was not saved' })).toBeVisible();
    await expect(page.getByTestId('rule-node-bad rule')).toHaveClass(/fnode-error/);
  });

  test('simulates a request and highlights its path', async ({ page }) => {
    await login(page);
    const sim = page.getByTestId('simulator');
    await sim.getByLabel('scores.l2', { exact: true }).fill('0.2');
    await sim.getByLabel('injection.score', { exact: true }).fill('0.7');
    await sim.getByRole('button', { name: 'Simulate' }).click();
    const result = page.getByTestId('sim-result');
    await expect(result).toContainText('route');
    await expect(result).toContainText('safe-model');
    await expect(result.locator('.trace li')).toHaveCount(3);
    await expect(page.locator('.react-flow__node.hl-match')).toHaveCount(1);
    await expect(page.locator('.react-flow__node.hl-match')).toContainText('suspicious to safe model');
    await expect(page.locator('.react-flow__node.hl-path').filter({ hasText: 'safe-model' })).toHaveCount(1);
  });
});
