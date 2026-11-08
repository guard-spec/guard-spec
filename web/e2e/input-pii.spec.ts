// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Personal data in requests (RF-474e756a): the Guard settings switch, rules
// on input.pii.kinds and input.pii.count in the Policy flow, and the
// Simulator. Screenshots go to test-results/input-pii/.

import { expect, go, login, test } from './fixtures';
import { EMAIL, PASSWORD } from './mockApi';

const SHOTS = 'test-results/input-pii';

test.describe('Personal data in requests', () => {
  test('the Guard settings switch is off by default, explains its coverage and saves', async ({ page, mock }) => {
    await login(page, null);
    await go(page, 'Guard settings');
    const sw = page.getByRole('switch', { name: 'Detect personal data in requests' });
    await expect(sw).not.toBeChecked();
    await expect(page.getByText('Off by default. When on, the gateway checks user messages, tool results and documents')).toBeVisible();

    // The tip says what is not covered.
    const tip = page.getByTestId('help-input-pii');
    await page.getByRole('group', { name: 'Personal data in requests' }).scrollIntoViewIfNeeded();
    await tip.hover();
    const pop = page.getByRole('tooltip').filter({ hasText: 'names, street addresses, bank account numbers' });
    await expect(pop).toBeVisible();
    await expect(pop).toContainText('1.2.3.4 reads as an IPv4 address');
    await page.screenshot({ path: `${SHOTS}/guard-settings-tip-en.png` });
    await page.mouse.move(0, 0);

    await sw.check();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Saved.')).toBeVisible();
    expect(mock.guard).toMatchObject({ input_pii: true });
    await page.screenshot({ path: `${SHOTS}/guard-settings-on-en.png` });

    // Turned off again, it is stored as false.
    await sw.uncheck();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(() => (mock.guard as { input_pii?: boolean }).input_pii).toBe(false);
  });

  test('the switch in Vietnamese', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('gs.lang', 'vi'));
    await page.goto('/ui/');
    await page.getByLabel('Email').fill(EMAIL);
    await page.getByLabel('Mật khẩu').fill(PASSWORD);
    await page.getByRole('button', { name: 'Đăng nhập' }).click();
    await page.getByTestId('my-orgs').getByRole('button').first().click();
    await page.getByRole('navigation', { name: 'Điều hướng chính' }).getByRole('link', { name: 'Thiết lập bảo vệ', exact: true }).click();
    await expect(page.getByRole('switch', { name: 'Phát hiện dữ liệu cá nhân trong request' })).toBeVisible();
    await expect(page.getByText('Mặc định tắt.')).toBeVisible();
    await page.getByRole('group', { name: 'Dữ liệu cá nhân trong request' }).scrollIntoViewIfNeeded();
    await page.getByTestId('help-input-pii').hover();
    await expect(page.getByRole('tooltip').filter({ hasText: 'không tìm được họ tên, địa chỉ nhà' })).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/guard-settings-tip-vi.png` });
  });

  test('creates a rule on input.pii.count, saves it and simulates it', async ({ page, mock }) => {
    await login(page);
    await page.getByRole('button', { name: '+ Add rule' }).first().click();
    const panel = page.getByTestId('rule-panel');
    await panel.getByLabel('Name').fill('block personal data');
    await panel.getByLabel('Action', { exact: true }).selectOption('block');

    // The field picker has a Personal data group with both fields.
    await panel.getByRole('button', { name: /^Field / }).first().click();
    const list = panel.getByRole('listbox');
    const group = list.getByRole('group', { name: 'Personal data' });
    await expect(group).toBeVisible();
    await expect(group.getByRole('option')).toHaveCount(2);
    await panel.getByRole('combobox', { name: 'Search fields' }).fill('input.pii.count');
    await expect(list.getByRole('option')).toHaveCount(1);
    await page.screenshot({ path: `${SHOTS}/field-picker-en.png` });
    await page.keyboard.press('Enter');
    await expect(panel.getByRole('button', { name: 'Field input.pii.count' })).toBeVisible();

    // Its help: description, values, example.
    await panel.getByTestId('help-input.pii.count').first().hover();
    const tip = page.getByRole('tooltip').filter({ hasText: 'How many values of personal data' });
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('input.pii.count > 0');
    await page.screenshot({ path: `${SHOTS}/field-help-en.png` });
    await page.mouse.move(0, 0);

    await panel.getByLabel('Operator').first().selectOption('>');
    await panel.locator('.rule-value').first().fill('0');
    await expect(page.getByTestId('condition-problems')).toHaveCount(0);
    await expect(page.getByTestId('rule-node-block personal data')).toContainText('input.pii.count > 0');

    // The Simulator takes the new fields and runs the unsaved rule.
    const sim = page.getByTestId('simulator');
    await sim.getByRole('button', { name: 'Clear' }).click();
    await sim.getByLabel('input.pii.kinds', { exact: true }).fill('email, card');
    await sim.getByLabel('input.pii.count', { exact: true }).fill('2');
    await sim.getByRole('button', { name: 'Simulate' }).click();
    const result = page.getByTestId('sim-result');
    await expect(result).toContainText('block');
    await expect(result.locator('.trace li.trace-hit')).toContainText('block personal data');
    const call = mock.calls.filter((c) => c.path.endsWith('/policies/simulate')).pop();
    expect((call?.body as { vars: Record<string, unknown> }).vars).toMatchObject({
      'input.pii.kinds': ['email', 'card'],
      'input.pii.count': 2,
    });
    await result.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/simulator-en.png` });

    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('Policies saved.')).toBeVisible();
    const put = mock.calls.filter((c) => c.method === 'PUT' && c.path.includes('/policies/')).pop();
    const rules = (put?.body as { rules: { name: string; action: string; condition: unknown }[] }).rules;
    const saved = rules.find((r) => r.name === 'block personal data');
    expect(saved?.action).toBe('block');
    expect(JSON.stringify(saved?.condition)).toContain('"field":"input.pii.count","operator":">","value":"0"');
  });

  test('a rule on input.pii.kinds picks one kind from the list', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: '+ Add rule' }).first().click();
    const panel = page.getByTestId('rule-panel');
    await panel.getByLabel('Name').fill('log cards');
    await panel.getByLabel('Action', { exact: true }).selectOption('log');
    await panel.getByRole('button', { name: /^Field / }).first().click();
    await panel.getByRole('combobox', { name: 'Search fields' }).fill('input.pii.kinds');
    await page.keyboard.press('Enter');
    await panel.locator('.rule-value').first().selectOption('card');
    await expect(page.getByTestId('condition-problems')).toHaveCount(0);
    await expect(page.getByTestId('rule-node-log cards')).toContainText('"card" in input.pii.kinds');
    // "in" reads the same: still one kind.
    await panel.getByLabel('Operator').first().selectOption('in');
    await expect(panel.locator('.rule-value').first()).not.toHaveAttribute('multiple', /.*/);
    await expect(page.getByTestId('condition-problems')).toHaveCount(0);
  });
});
