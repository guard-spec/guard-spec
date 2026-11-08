// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Real-time alerts and notifications (RF-35448968) against the mocked
// alerts contract (e2e/mockAlerts.ts).

import type { Page } from '@playwright/test';
import { expect, go, login, openProfile, test } from './fixtures';
import { CHANNEL_LINK_CODE, EMAIL_CODE, LINKED_GROUP_CHAT, pushNotification, TELEGRAM_BOT, TELEGRAM_CODE } from './mockAlerts';

async function clearEditor(page: Page) {
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('Delete');
}

test('creates an alert rule with every field', async ({ page, mock }) => {
  await login(page, 'Alert rules');
  const table = page.getByTestId('alert-rules-table');
  await expect(table).toContainText('Jailbreak burst');
  await page.getByRole('button', { name: 'New rule' }).click();
  const dialog = page.getByRole('dialog', { name: 'New rule' });
  const editor = dialog.getByTestId('rule-editor');

  // Nothing filled in: every problem is named.
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(editor.getByText('Fix the fields marked below.')).toBeVisible();

  await editor.getByLabel('Name', { exact: true }).fill('Exfiltration in billing');
  await editor.getByLabel('Severity').selectOption('critical');
  await editor.getByLabel('detection.flagged').check();
  await editor.getByLabel('upstream.error').check();
  await editor.getByLabel('upstream.error').uncheck();

  // The condition: a parse error in the text tab, then a valid one, shown in the visual tab too.
  await editor.getByRole('tab', { name: 'Text' }).click();
  const text = editor.getByTestId('alert-condition-text');
  await text.click();
  await clearEditor(page);
  await page.keyboard.type('attrs.score >= "high"');
  await expect(editor.getByTestId('alert-condition-error')).toContainText('attrs.score is a number');
  await editor.getByRole('tab', { name: 'Visual' }).click();
  await expect(editor.getByText('The text does not parse.')).toBeVisible();
  await editor.getByRole('tab', { name: 'Text' }).click();
  await text.click();
  await clearEditor(page);
  await page.keyboard.type('"exfiltration" in attrs.categories && attrs.score >= 0.8');
  await expect(editor.getByTestId('alert-condition-error')).toHaveCount(0);
  await editor.getByRole('tab', { name: 'Visual' }).click();
  await expect(editor.locator('.qb-wrap .rule')).toHaveCount(2);

  await editor.getByLabel('Threshold (events)').fill('3');
  await editor.getByLabel('Window (seconds)').fill('600');
  await expect(editor.getByText('= 10 min')).toBeVisible();
  await editor.getByLabel('Throttle (seconds)').fill('1800');
  await editor.getByLabel('project_id').check();
  await editor.getByLabel('attrs.category').check();
  await editor.getByLabel('Auto-resolve').check();
  await editor.getByLabel('Use quiet hours').check();
  await editor.getByLabel('Time zone').fill('Asia/Ho_Chi_Minh');
  await editor.getByLabel('During quiet hours').selectOption('delay');
  await editor.getByRole('checkbox', { name: 'Security on-call' }).check();
  await editor.getByRole('checkbox', { name: 'Admin', exact: true }).check();
  await editor.getByRole('checkbox', { name: /^siem-webhook/ }).check();
  await editor.getByTestId('rule-users').getByPlaceholder('Search members').fill('bình');
  await editor.getByTestId('rule-users').getByRole('checkbox').first().check();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  await expect(table).toContainText('Exfiltration in billing');

  const rule = mock.alerts.rules.find((r) => r.name === 'Exfiltration in billing');
  expect(rule).toMatchObject({
    enabled: true,
    severity: 'critical',
    event_types: ['detection.blocked', 'detection.flagged'],
    condition: '"exfiltration" in attrs.categories && attrs.score >= 0.8',
    threshold: 3,
    window_seconds: 600,
    throttle_seconds: 1800,
    group_by: ['project_id', 'attrs.category'],
    auto_resolve: true,
    quiet_hours: { tz: 'Asia/Ho_Chi_Minh', start: '22:00', end: '07:00', mode: 'delay', critical_bypass: true },
    recipients: { group_ids: [mock.alerts.groups[0]?.id], roles: ['admin'] },
    channel_ids: [mock.alerts.channels[1]?.id],
  });
  expect(rule?.recipients?.user_ids).toHaveLength(1);

  // The enable switch and "Send test" on the list.
  await page.getByRole('switch', { name: 'Enabled: Exfiltration in billing' }).uncheck();
  await expect.poll(() => mock.alerts.rules.find((r) => r.name === 'Exfiltration in billing')?.enabled).toBe(false);
  await page.getByRole('button', { name: 'Send a test of Exfiltration in billing' }).click();
  await expect(page.getByRole('status').getByText(/Test of Exfiltration in billing sent/)).toBeVisible();
  expect(mock.alerts.alerts[0]?.rule_id).toBe(rule?.id);
});

test('channels: per-kind forms, env names, secret_set and test results', async ({ page, mock }) => {
  await login(page, 'Channels');
  const table = page.getByTestId('channels-table');
  await expect(table).toContainText('$SLACK_WEBHOOK_SECOPS');
  await expect(table.getByRole('row').filter({ hasText: 'it-teams' })).toContainText('Not set');
  await expect(table.getByRole('row').filter({ hasText: 'secops-slack' })).toContainText('Set');
  // Email has no secret: the instance SMTP sends it.
  await expect(table.getByRole('row').filter({ hasText: 'security-mailbox' })).toContainText('Instance SMTP');

  await page.getByRole('button', { name: 'Send a test to secops-slack' }).click();
  let result = page.getByTestId('channel-test-result');
  await expect(result).toContainText('Test of secops-slack');
  await expect(result).toContainText('Delivered');
  await expect(result).toContainText('HTTP 200');
  await expect(result).toContainText('183 ms');
  await result.getByRole('button', { name: 'Dismiss' }).click();

  await page.getByRole('button', { name: 'Send a test to siem-webhook' }).click();
  result = page.getByTestId('channel-test-result');
  await expect(result).toContainText('Failed');
  await expect(result).toContainText('HTTP 502');
  await expect(result).toContainText('341 ms');
  await expect(result).toContainText('HTTP 502 from siem.acme.example (path redacted)');
  await page.getByRole('button', { name: 'Send a test to it-teams' }).click();
  await expect(page.getByTestId('channel-test-result').filter({ hasText: 'it-teams' })).toContainText('TEAMS_WEBHOOK_IT is not set on the control plane');

  // A new webhook: https only, and only allowed env names.
  await page.getByRole('button', { name: 'New channel' }).click();
  const dialog = page.getByRole('dialog', { name: 'New channel' });
  await dialog.getByLabel('Kind').selectOption('webhook');
  await expect(dialog.getByText('HMAC signing secret, e.g. WEBHOOK_SECRET_SIEM')).toBeVisible();
  await dialog.getByLabel('Name', { exact: true }).fill('soar');
  await dialog.getByLabel('Endpoint URL').fill('http://10.0.0.5/hook');
  await dialog.getByLabel('Secret variable').fill('database_url');
  await expect(dialog.getByLabel('Secret variable')).toHaveValue('DATABASE_URL');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByText('An https:// URL.')).toBeVisible();
  await expect(dialog.getByText('For this kind the name must start with one of: WEBHOOK_SECRET_, GUARDSPEC_ALERT_.')).toBeVisible();
  // The helper names the operator's binding for this kind and org.
  await expect(dialog.getByText(/ALERTS_SECRET_ORGS, e\.g\. WEBHOOK_SECRET_SIEM=webhook:00000000-0000-0000-0000-000000000001/)).toBeVisible();
  // The private-network switch shows only when the instance allows it.
  await expect(dialog.getByLabel('Allow a private address')).toHaveCount(0);
  await dialog.getByLabel('Endpoint URL').fill('https://soar.acme.example/in');
  // Not bound to webhook channels of this org in ALERTS_SECRET_ORGS: the server's 400, under the field.
  await dialog.getByLabel('Secret variable').fill('WEBHOOK_SECRET_SOAR');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByText(/WEBHOOK_SECRET_SOAR is not listed for webhook channels of this organization in ALERTS_SECRET_ORGS/)).toBeVisible();
  await dialog.getByLabel('Secret variable').fill('WEBHOOK_SECRET_SOC');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  const row = table.getByRole('row').filter({ hasText: 'soar' });
  await expect(row).toContainText('https://soar.acme.example/in');
  await expect(row).toContainText('Not set');
  expect(mock.alerts.channels.at(-1)).toMatchObject({ kind: 'webhook', config: { url: 'https://soar.acme.example/in', allow_private: false }, secret_env: 'WEBHOOK_SECRET_SOC' });
  // Capabilities are asked for this org (allow_private_urls is per org).
  expect(mock.alerts.capsCalls).toContain(mock.org.id);

  // Slack in bot mode needs a channel.
  await page.getByRole('button', { name: 'Edit channel secops-slack' }).click();
  const edit = page.getByRole('dialog', { name: 'Edit channel' });
  await expect(edit.getByLabel('Kind')).toBeDisabled();
  await edit.getByLabel('Bot token').check();
  await expect(edit.getByText('Slack bot token (xoxb-…), e.g. SLACK_BOT_TOKEN_OPS')).toBeVisible();
});

test('incident tools: a PagerDuty channel with its region and routing key variable', async ({ page, mock }) => {
  await login(page, 'Channels');
  await page.getByRole('button', { name: 'New channel' }).click();
  const dialog = page.getByRole('dialog', { name: 'New channel' });
  await dialog.getByLabel('Kind').selectOption('pagerduty');
  await expect(dialog.getByText(/Events API v2 integration/)).toBeVisible();
  await expect(dialog.getByText('The variable that holds the routing key, e.g. PAGERDUTY_ROUTING_KEY_SEC.', { exact: false })).toBeVisible();
  await dialog.getByLabel('Name', { exact: true }).fill('sec-on-call');
  await dialog.getByLabel('Region').selectOption('eu');
  await dialog.getByLabel('Secret variable').fill('OPSGENIE_KEY');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByText('For this kind the name must start with one of: PAGERDUTY_, GUARDSPEC_ALERT_.')).toBeVisible();
  await dialog.getByLabel('Secret variable').fill('PAGERDUTY_ROUTING_KEY_SEC');
  await page.screenshot({ path: 'test-results/shots/pagerduty-en.png' });
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog).toBeHidden();
  const row = page.getByTestId('channels-table').getByRole('row').filter({ hasText: 'sec-on-call' });
  await expect(row).toContainText('PagerDuty');
  await expect(row).toContainText('events api (eu)');
  expect(mock.alerts.channels.at(-1)).toMatchObject({ kind: 'pagerduty', config: { region: 'eu' }, secret_env: 'PAGERDUTY_ROUTING_KEY_SEC' });
  await page.screenshot({ path: 'test-results/shots/channels-incident-en.png' });
});

test('telegram on the instance bot: created without a chat id, verified with /link', async ({ page, mock }) => {
  await login(page, 'Channels');
  const table = page.getByTestId('channels-table');
  const soc = table.getByRole('row').filter({ hasText: 'soc-group-telegram' }).first();
  await expect(soc).toContainText('Not verified');
  // An unverified channel cannot send.
  await page.getByRole('button', { name: 'Send a test to soc-group-telegram' }).click();
  await expect(page.getByTestId('channel-test-result').filter({ hasText: 'soc-group-telegram' })).toContainText('not verified');

  await page.getByRole('button', { name: 'New channel' }).click();
  const dialog = page.getByRole('dialog', { name: 'New channel' });
  await dialog.getByLabel('Kind').selectOption('telegram');
  await dialog.getByLabel('Name', { exact: true }).fill('fraud-telegram');
  await expect(dialog.getByTestId('telegram-instance-help')).toContainText(`@${TELEGRAM_BOT}`);
  await expect(dialog.getByLabel('Group chat id')).toHaveCount(0);
  // Its own bot names the chat.
  await dialog.getByLabel('Secret variable').fill('TELEGRAM_BOT_TOKEN_FRAUD');
  await expect(dialog.getByLabel('Group chat id')).toBeVisible();
  await dialog.getByLabel('Secret variable').fill('');
  await expect(dialog.getByLabel('Group chat id')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Save' }).click();
  const created = mock.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/notification-channels')).at(-1);
  expect(created?.body).toMatchObject({ kind: 'telegram', config: {}, secret_env: null });

  // Saved: the /link step opens, and the channel is polled until verified.
  const verify = page.getByRole('dialog', { name: 'Verify fraud-telegram' });
  await expect(verify.getByTestId('telegram-link-command')).toHaveText(`/link@${TELEGRAM_BOT} ${CHANNEL_LINK_CODE}`);
  await expect(verify.getByRole('button', { name: 'Copy' })).toBeVisible();
  await expect(verify).toContainText('Waiting for the group');
  await expect(verify).toBeHidden({ timeout: 10_000 });
  await expect(page.getByRole('status').getByText('fraud-telegram is verified.')).toBeVisible();
  const row = table.getByRole('row').filter({ hasText: 'fraud-telegram' });
  await expect(row).toContainText(LINKED_GROUP_CHAT);
  await expect(row).not.toContainText('Not verified');

  // The existing one: the Verify action.
  await page.getByRole('button', { name: 'Verify soc-group-telegram' }).click();
  await expect(page.getByRole('dialog', { name: 'Verify soc-group-telegram' }).getByTestId('telegram-link-command')).toBeVisible();
  await expect(page.getByRole('dialog', { name: 'Verify soc-group-telegram' })).toBeHidden({ timeout: 10_000 });
  await expect(soc).not.toContainText('Not verified');
});

test('email channels: confirmation status and resend', async ({ page, mock }) => {
  await login(page, 'Channels');
  const row = page.getByTestId('channels-table').getByRole('row').filter({ hasText: 'security-mailbox' });
  await expect(row).toContainText('1/2 confirmed');
  const before = mock.alerts.channels.find((c) => c.name === 'security-mailbox')?.addresses?.[1]?.sent_at;
  await page.getByRole('button', { name: 'Resend confirmation for security-mailbox' }).click();
  await expect(page.getByRole('status').getByText('Confirmation links sent to 1 addresses of security-mailbox.')).toBeVisible();
  expect(mock.calls.some((c) => c.method === 'POST' && c.path.endsWith('/email-confirmations'))).toBe(true);
  expect(mock.alerts.channels.find((c) => c.name === 'security-mailbox')?.addresses?.[1]?.sent_at).not.toBe(before);

  await page.getByRole('button', { name: 'Edit channel security-mailbox' }).click();
  const list = page.getByRole('dialog', { name: 'Edit channel' }).getByTestId('email-addresses');
  await expect(list.getByRole('listitem').filter({ hasText: 'security@acme.example' })).toContainText('Confirmed');
  await expect(list.getByRole('listitem').filter({ hasText: 'ciso@acme.example' })).toContainText('Waiting for confirmation');
  await expect(page.getByRole('dialog', { name: 'Edit channel' })).toContainText('at most 500 emails a day');
});

test('private addresses only for orgs the operator allows', async ({ page, mock }) => {
  mock.alerts.privateOrg = true;
  await login(page, 'Channels');
  await page.getByRole('button', { name: 'New channel' }).click();
  const dialog = page.getByRole('dialog', { name: 'New channel' });
  await dialog.getByLabel('Kind').selectOption('webhook');
  await expect(dialog.getByLabel('Allow a private address')).toBeVisible();
  await expect(dialog).toContainText('ALERTS_PRIVATE_ORGS');
  await expect(dialog).toContainText('timestamp + "." + event_id + "." + body');
});

test('groups: create one and pick its members', async ({ page, mock }) => {
  await login(page, 'Groups');
  const table = page.getByTestId('groups-table');
  await expect(table.getByRole('row').filter({ hasText: 'Security on-call' })).toContainText('Members: 3');
  await page.getByRole('button', { name: 'Members of Platform team' }).click();
  const dialog = page.getByRole('dialog', { name: 'Members of Platform team' });
  const picker = dialog.getByTestId('group-members-picker');
  await expect(picker.getByText('1 selected')).toBeVisible();
  await picker.getByRole('checkbox', { name: /Ada Admin/ }).check();
  await picker.getByPlaceholder('Search members').fill('emma');
  await picker.getByRole('checkbox').first().check();
  await expect(picker.getByText('3 selected')).toBeVisible();
  await dialog.getByRole('button', { name: 'Save members' }).click();
  await expect(dialog).toBeHidden();
  await expect(table.getByRole('row').filter({ hasText: 'Platform team' })).toContainText('Members: 3');
  const g = mock.alerts.groups.find((x) => x.name === 'Platform team');
  expect(g?.user_ids).toHaveLength(3);
  expect(g?.user_ids).toContain(mock.identity.me.id);

  await page.getByRole('button', { name: 'New group' }).click();
  const create = page.getByRole('dialog', { name: 'New group' });
  await create.getByLabel('Name', { exact: true }).fill('Compliance');
  await create.getByLabel('Description').fill('Weekly digest readers');
  await create.getByRole('button', { name: 'Save' }).click();
  // A new group opens its members.
  await expect(page.getByRole('dialog', { name: 'Members of Compliance' })).toBeVisible();
  await page.getByRole('dialog', { name: 'Members of Compliance' }).getByRole('button', { name: 'Cancel' }).click();
  await expect(table).toContainText('Weekly digest readers');
});

test('the bell counts unread notifications and updates live from the stream', async ({ page, mock }) => {
  await login(page, null);
  const bell = page.getByTestId('bell');
  await expect(bell).toHaveAccessibleName('Notifications, 2 unread');
  await expect.poll(() => mock.alerts.streams.length).toBeGreaterThan(0);
  // fetch streaming with the Bearer header, never the token in the URL.
  expect(mock.alerts.streams[0]?.auth).toBe('Bearer mock-token-abc');
  expect(mock.alerts.streams[0]?.url).not.toContain('mock-token');
  expect(new URL(mock.alerts.streams[0]?.url ?? 'http://x/').search).toBe('');

  pushNotification(mock.alerts, { alert_id: mock.alerts.alerts[0]?.id ?? null, title: 'Exfiltration attempt blocked', body: '3 requests in 5 min · project support', severity: 'critical' });
  await expect(bell).toHaveAccessibleName('Notifications, 3 unread', { timeout: 10_000 });
  await expect(page.getByTestId('bell-count')).toHaveText('3');

  await bell.click();
  const panel = page.getByRole('group', { name: 'Notifications' });
  await expect(panel.getByTestId('bell-list').getByRole('listitem').first()).toContainText('Exfiltration attempt blocked');
  await panel.getByRole('button', { name: 'Mark read: Exfiltration attempt blocked' }).click();
  await expect(bell).toHaveAccessibleName('Notifications, 2 unread');
  expect(mock.calls.find((c) => c.path === '/notifications/read')?.body).toEqual({ ids: [mock.alerts.notifications[0]?.id] });

  // A notification opens its alert.
  await panel.getByRole('link', { name: /Jailbreak burst firing/ }).click();
  await expect(page.getByRole('heading', { name: 'Alert history', level: 1 })).toBeVisible();
  await expect(page.getByTestId('alert-detail')).toContainText(mock.alerts.alerts[0]?.id ?? 'missing');
  await expect(bell).toHaveAccessibleName('Notifications, 1 unread');
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).last().click();

  await bell.click();
  await page.getByRole('group', { name: 'Notifications' }).getByRole('button', { name: 'Mark all read' }).click();
  await expect(bell).toHaveAccessibleName('Notifications');
  await expect(page.getByTestId('bell-count')).toHaveCount(0);
});

test('my account: link Telegram with a code, link Slack, set preferences', async ({ page, mock }) => {
  await login(page, null);
  await openProfile(page);
  await page.getByRole('link', { name: 'My account' }).click();
  const card = page.getByTestId('notification-settings');
  await expect(card).toContainText(`private chat with @${TELEGRAM_BOT}`);
  await card.getByRole('button', { name: 'Link Telegram' }).click();
  const linking = card.getByTestId('telegram-link');
  await expect(linking.getByTestId('telegram-code')).toHaveText(`/start ${TELEGRAM_CODE}`);
  await expect(linking.getByTestId('telegram-deeplink')).toHaveAttribute('href', `https://t.me/${TELEGRAM_BOT}?start=${TELEGRAM_CODE}`);
  await expect(linking.getByTestId('telegram-deeplink')).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(linking).toContainText('Waiting for Telegram');
  // The page polls until the bot reports the /start.
  await expect(card).toContainText('Linked: @ada_admin (chat 551234987)', { timeout: 10_000 });
  await expect(linking).toHaveCount(0);

  await card.getByRole('button', { name: 'Link Slack' }).click();
  await expect(card).toContainText('Linked: U07ADAADMIN');
  await expect(card).toContainText(`Sent to ${mock.identity.me.email}`);

  const prefs = card.getByTestId('notif-prefs');
  await prefs.getByRole('switch', { name: 'Telegram on' }).check();
  await prefs.getByLabel('Lowest severity for Telegram').selectOption('critical');
  await card.getByRole('button', { name: 'Save preferences' }).click();
  await expect.poll(() => mock.alerts.prefs).toEqual([
    { channel_kind: 'telegram', enabled: true, min_severity: 'critical' },
    { channel_kind: 'slack', enabled: true, min_severity: 'info' },
    { channel_kind: 'email', enabled: true, min_severity: 'critical' },
  ]);

  await card.getByRole('button', { name: 'Unlink Telegram' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Unlink' }).click();
  await expect(card.getByRole('button', { name: 'Link Telegram' })).toBeVisible();
  expect(mock.alerts.links.map((l) => l.kind)).toEqual(['slack']);
});

test('my account: another email address, confirmed with a code', async ({ page, mock }) => {
  await login(page, null);
  await page.goto('/ui/account');
  const row = page.getByTestId('email-link');
  await expect(row).toContainText(`Sent to ${mock.identity.me.email}`);
  await row.getByRole('button', { name: 'Use another address' }).click();
  await row.getByLabel('New email address').fill('ada.oncall@acme.example');
  await row.getByRole('button', { name: 'Send code' }).click();
  const pending = row.getByTestId('email-pending');
  await expect(pending).toContainText('Code sent to ada.oncall@acme.example');
  expect(mock.calls.find((c) => c.method === 'PUT' && c.path === '/me/channel-links/email')?.body).toEqual({ address: 'ada.oncall@acme.example' });
  // One code a minute.
  await pending.getByRole('button', { name: 'Send again' }).click();
  await expect(row.getByRole('alert')).toContainText('less than a minute ago');
  // A wrong code, then the right one.
  await pending.getByLabel('Code from the email').fill('000000');
  await pending.getByRole('button', { name: 'Confirm' }).click();
  await expect(row.getByRole('alert')).toContainText('The code was not accepted: wrong, expired or used-up code');
  await pending.getByLabel('Code from the email').fill(EMAIL_CODE);
  await pending.getByRole('button', { name: 'Confirm' }).click();
  await expect(row).toContainText('Sent to ada.oncall@acme.example');
  await expect(row).toContainText(`Instead of the account address (${mock.identity.me.email})`);
  await expect(row.getByTestId('email-pending')).toHaveCount(0);

  // A pending address shows next to the verified one.
  mock.alerts.emailCodeAt = null;
  await row.getByRole('button', { name: 'Use another address' }).click();
  await row.getByLabel('New email address').fill('ada.second@acme.example');
  await row.getByRole('button', { name: 'Send code' }).click();
  await expect(row).toContainText('Sent to ada.oncall@acme.example');
  await expect(row.getByTestId('email-pending')).toContainText('ada.second@acme.example');

  // Back to the account address.
  await row.getByRole('button', { name: 'Use the account address again' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Unlink' }).click();
  await expect(row).toContainText(`Sent to ${mock.identity.me.email}`);
});

test('my account hides channels the instance cannot deliver', async ({ page, mock }) => {
  mock.alerts.caps = { ...mock.alerts.caps, telegram: { enabled: false }, slack_bot: false };
  await login(page, null);
  await page.goto('/ui/account');
  const card = page.getByTestId('notification-settings');
  await expect(card).toContainText('Email');
  await expect(card.getByRole('button', { name: 'Link Telegram' })).toHaveCount(0);
  await expect(card.getByRole('button', { name: 'Link Slack' })).toHaveCount(0);
  await expect(card.getByTestId('notif-prefs').getByRole('row')).toHaveCount(2);
});

test('a viewer sees the alert pages read-only', async ({ page }) => {
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  const { installMockApi, seedState } = await import('./mockApi');
  await installMockApi(page, seedState(), { role: 'viewer' });
  await login(page, 'Alert rules');
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'Delivery log' })).toHaveCount(0);
  await expect(page.getByText('Your role can view alerting but not change it.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'New rule' })).toHaveCount(0);
  await expect(page.getByRole('switch', { name: 'Enabled: Jailbreak burst' })).toBeDisabled();
  await expect(page.getByRole('button', { name: /^Send a test of/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'View Jailbreak burst' }).click();
  const dialog = page.getByRole('dialog', { name: 'Alert rule' });
  await expect(dialog.getByLabel('Name', { exact: true })).toBeDisabled();
  await expect(dialog.getByLabel('Threshold (events)')).toBeDisabled();
  await expect(dialog.getByRole('button', { name: 'Save' })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Close' }).last().click();

  await go(page, 'Channels');
  await expect(page.getByRole('button', { name: 'New channel' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Send a test to/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Delete / })).toHaveCount(0);
  await go(page, 'Groups');
  await expect(page.getByRole('button', { name: 'New group' })).toHaveCount(0);
  await page.getByRole('button', { name: 'View Security on-call' }).click();
  await expect(page.getByRole('dialog').getByRole('checkbox').first()).toBeDisabled();
  await expect(page.getByRole('dialog').getByRole('button', { name: 'Save members' })).toHaveCount(0);
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).last().click();
  await go(page, 'Alert history');
  await expect(page.getByTestId('alerts-table')).toContainText('Jailbreak burst');
  // The delivery log is for admins: the server refuses it.
  await page.goto('/ui/alerts/deliveries');
  await expect(page.getByText('You don’t have permission')).toBeVisible();
});

test('alert history filters and opens an alert; the delivery log shows errors', async ({ page }) => {
  await login(page, 'Alert history');
  const table = page.getByTestId('alerts-table');
  await expect(table.getByRole('row')).toHaveCount(7);
  await page.getByLabel('State').selectOption('firing');
  await expect(table.getByRole('row')).toHaveCount(3);
  await page.getByRole('button', { name: 'View alert of Jailbreak burst' }).click();
  const detail = page.getByTestId('alert-detail');
  await expect(detail).toContainText('project_id=support');
  await expect(detail).toContainText('detection.blocked');
  await expect(detail).toContainText('categories=jailbreak');
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).last().click();

  await go(page, 'Delivery log');
  const log = page.getByTestId('deliveries-table');
  await expect(log.getByTestId('delivery-error').first()).toBeVisible();
  await page.getByLabel('State').selectOption('dead');
  await expect(log.getByTestId('delivery-error')).toHaveCount(1);
  await expect(log).toContainText('channel_not_found');
  await expect(log).not.toContainText('hooks.slack.com/services/T');
  await page.getByLabel('State').selectOption('');
  await page.getByLabel('Channel').selectOption('telegram');
  await expect(log.getByRole('row').filter({ hasText: 'Webhook' })).toHaveCount(0);
});

test('alert pages in Vietnamese', async ({ page }) => {
  await login(page, null);
  await page.evaluate(() => localStorage.setItem('gs.lang', 'vi'));
  await page.goto('/ui/alerts/rules');
  await expect(page.getByRole('heading', { name: 'Quy tắc cảnh báo', level: 1 })).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Điều hướng chính' });
  await expect(nav.getByRole('link', { name: 'Nhật ký gửi' })).toBeVisible();
  await expect(page.getByTestId('alert-rules-table')).toContainText('Nghiêm trọng');
  await expect(page.getByTestId('bell')).toHaveAccessibleName('Thông báo, 2 chưa đọc');
});

/** The same check as polish.spec.ts: tables that scroll sideways or come within 32px of it. */
const HEADROOM = 32;
async function overflows(page: Page): Promise<string[]> {
  return page.evaluate((headroom) => {
    const out: string[] = [];
    document.querySelectorAll<HTMLElement>('.table-wrap').forEach((el) => {
      const table = el.querySelector('table');
      const name = table?.dataset.testid ?? '?';
      if (el.scrollWidth > el.clientWidth + 1) out.push(`table ${name}: ${el.scrollWidth} > ${el.clientWidth}`);
      if (table) {
        const before = table.style.width;
        table.style.width = 'min-content';
        const min = table.offsetWidth;
        table.style.width = before;
        if (min > el.clientWidth - headroom) out.push(`table ${name}: needs ${min}px of ${el.clientWidth}px (headroom ${headroom}px)`);
      }
    });
    if (document.documentElement.scrollWidth > window.innerWidth + 1) out.push(`page: ${document.documentElement.scrollWidth} > ${window.innerWidth}`);
    return out;
  }, HEADROOM);
}

test.describe('layout', () => {
  test.use({ mockOptions: { rich: true } });
  for (const lang of ['en', 'vi'] as const) {
    test(`every alerts table fits at 1280px (${lang})`, async ({ page }) => {
      test.setTimeout(60_000);
      await page.setViewportSize({ width: 1280, height: 900 });
      await login(page, null);
      if (lang === 'vi') await page.evaluate(() => localStorage.setItem('gs.lang', 'vi'));
      const found: string[] = [];
      for (const path of ['alerts/rules', 'alerts/channels', 'alerts/groups', 'alerts/history', 'alerts/deliveries']) {
        await page.goto(`/ui/${path}`);
        await expect(page.locator('.table-wrap table')).toBeVisible();
        await page.locator('.skeleton').first().waitFor({ state: 'detached' }).catch(() => undefined);
        await page.waitForTimeout(150);
        found.push(...(await overflows(page)).map((o) => `${path}: ${o}`));
      }
      // With a test result under a row.
      await page.goto('/ui/alerts/channels');
      await page.locator('button[aria-label^="Send a test to siem-webhook"], button[aria-label^="Gửi thử tới siem-webhook"]').click();
      await expect(page.getByTestId('channel-test-result')).toBeVisible();
      found.push(...(await overflows(page)).map((o) => `channels with a test result: ${o}`));
      expect(found).toEqual([]);
    });
  }
});
