// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi as viMessages } from '../i18n/vi';
import { NAV } from '../nav';
import { PATHS, resolve } from '../router';
import { asNotification } from './api';
import { ALERT_SCHEMA, alertConditionText, ConditionParseError, parseAlertCondition } from './condition';
import { needsTelegramLink, unconfirmed } from './ChannelsPage';
import { groupMemberCount, groupMemberIds } from './GroupsPage';
import {
  channelBody,
  channelTarget,
  envNameProblem,
  formatSeconds,
  newRule,
  nextUnread,
  ruleBody,
  ruleInput,
  validateChannel,
  validateRule,
} from './model';
import { activeLink, availableKinds, fillPrefs, pendingEmail } from './NotificationSettings';
import { applyEvent } from './notifications';
import { backoffDelay, readStream, SseParser } from './sse';
import type { AppNotification, ChannelInput } from './types';

describe('alert conditions', () => {
  it('parses the policy-text subset over event fields', () => {
    const tree = parseAlertCondition('attrs.score >= 0.9 && ("jailbreak" in attrs.categories || type == "detection.flagged")');
    expect(tree).toEqual({
      combinator: 'and',
      rules: [
        { field: 'attrs.score', operator: '>=', value: 0.9 },
        {
          combinator: 'or',
          rules: [
            { field: 'attrs.categories', operator: 'contains', value: 'jailbreak' },
            { field: 'type', operator: '=', value: 'detection.flagged' },
          ],
        },
      ],
    });
  });

  it('reads in-lists, string methods and negation', () => {
    expect(parseAlertCondition('attrs.error_kind in ["timeout", "5xx"]').rules[0]).toEqual({ field: 'attrs.error_kind', operator: 'in', value: ['timeout', '5xx'] });
    expect(parseAlertCondition('attrs.model.startsWith("gpt-")').rules[0]).toEqual({ field: 'attrs.model', operator: 'beginsWith', value: 'gpt-' });
    expect(parseAlertCondition('!(severity == "info")')).toMatchObject({ not: true, rules: [{ field: 'severity', operator: '=', value: 'info' }] });
  });

  it('treats empty text as "always" and reports errors with a position', () => {
    expect(parseAlertCondition('  ')).toEqual({ combinator: 'and', rules: [] });
    const bad = (s: string) => {
      try {
        parseAlertCondition(s);
        return null;
      } catch (e) {
        return e instanceof ConditionParseError ? e.position : -1;
      }
    };
    expect(bad('prompt.text == "x"')).toBe(0);
    expect(bad('attrs.score >= "high"')).toBe(15);
    expect(bad('type > 3')).toBe(5);
    expect(bad('severity == "info" &&')).toBe(21);
  });

  it('round-trips builder trees to text, dropping half-filled rows', () => {
    const text = 'attrs.score >= 0.9 && attrs.error_kind in ["timeout", "5xx"]';
    expect(alertConditionText(parseAlertCondition(text))).toBe(text);
    expect(alertConditionText({ combinator: 'and', rules: [{ field: 'attrs.model', operator: '=', value: '' }] })).toBe('');
    expect(alertConditionText({ combinator: 'or', rules: [] })).toBe('');
    // Every field of the schema parses back.
    for (const f of ALERT_SCHEMA.fields) {
      const v = f.type === 'double' || f.type === 'int' ? 1 : f.type === 'list' ? 'x' : (f.values?.[0] ?? 'x');
      const leaf = { field: f.name, operator: f.type === 'list' ? 'contains' : '=', value: v };
      const s = alertConditionText({ combinator: 'and', rules: [leaf] });
      expect(parseAlertCondition(s).rules[0]).toEqual(leaf);
    }
  });
});

describe('alert rule form', () => {
  const valid = () => ({ ...newRule(), name: 'Jailbreak burst', recipients: { user_ids: [], group_ids: [], roles: ['admin' as const] } });

  it('accepts a complete rule and lists every problem of a bad one', () => {
    expect(validateRule(valid())).toEqual({});
    const bad = validateRule({
      ...newRule(),
      event_types: [],
      threshold: 0,
      window_seconds: 30,
      throttle_seconds: -1,
      condition: 'attrs.score >',
      quiet_hours: { tz: 'Asia/Ho_Chi_Minh', start: '22:00', end: '22:00', mode: 'delay', critical_bypass: true },
    });
    expect(Object.keys(bad).sort()).toEqual(['condition', 'event_types', 'name', 'quiet_hours', 'recipients', 'threshold', 'throttle_seconds', 'window_seconds']);
    expect(validateRule({ ...valid(), window_seconds: 86400, threshold: 3.5 }).threshold).toBe('threshold');
  });

  it('a shared channel alone is a recipient', () => {
    expect(validateRule({ ...valid(), recipients: { user_ids: [], group_ids: [], roles: [] }, channel_ids: ['c1'] }).recipients).toBeUndefined();
  });

  it('sends trimmed fields in contract order and fills a partial server rule', () => {
    const body = ruleBody({ ...valid(), name: '  x  ', condition: ' type == "alert.test" ', group_by: ['attrs.upstream_id', 'project_id'], recipients: { user_ids: [], group_ids: [], roles: ['owner', 'admin'] } });
    expect(body.name).toBe('x');
    expect(body.condition).toBe('type == "alert.test"');
    expect(body.group_by).toEqual(['project_id', 'attrs.upstream_id']);
    expect(body.recipients.roles).toEqual(['admin', 'owner']);
    const filled = ruleInput({ name: 'r', recipients: { user_ids: ['u'] }, channel_ids: null });
    expect(filled.recipients).toEqual({ user_ids: ['u'], group_ids: [], roles: [] });
    expect(filled.channel_ids).toEqual([]);
    expect(filled.window_seconds).toBe(300);
  });

  it('formats durations', () => {
    expect(formatSeconds(300)).toBe('5 min');
    expect(formatSeconds(5400)).toBe('1 h 30 min');
    expect(formatSeconds(86400)).toBe('1 d');
    expect(formatSeconds(45)).toBe('45 s');
  });
});

describe('channels', () => {
  const ch = (patch: Partial<ChannelInput>): ChannelInput => ({ name: 'ops', kind: 'webhook', config: { url: 'https://siem.example.com/h' }, secret_env: 'WEBHOOK_SECRET_SIEM', enabled: true, ...patch });

  it('allows only the contract env names', () => {
    expect(envNameProblem('TELEGRAM_BOT_TOKEN_OPS')).toBeNull();
    expect(envNameProblem('GUARDSPEC_ALERT_X')).toBeNull();
    expect(envNameProblem('DATABASE_URL')).toBe('prefix');
    expect(envNameProblem('slack_token')).toBe('format');
    expect(envNameProblem('SL')).toBe('format');
    expect(envNameProblem(`SLACK_${'A'.repeat(60)}`)).toBe('format');
    // Bound to the kind's prefix (or GUARDSPEC_ALERT_); never the instance tokens.
    expect(envNameProblem('SLACK_SOC', 'a2a')).toBe('prefix');
    expect(envNameProblem('A2A_SOC', 'a2a')).toBeNull();
    expect(envNameProblem('GUARDSPEC_ALERT_SOC', 'webhook')).toBeNull();
    expect(envNameProblem('SLACK_BOT_TOKEN', 'slack')).toBe('instance');
    expect(envNameProblem('TELEGRAM_BOT_TOKEN', 'telegram')).toBe('instance');
  });

  it('validates per kind', () => {
    expect(validateChannel(ch({}))).toEqual({});
    expect(validateChannel(ch({ config: { url: 'http://10.0.0.5/h' } })).url).toBe('https');
    expect(validateChannel(ch({ config: { url: 'http://10.0.0.5/h', allow_private: true } }), true).url).toBeUndefined();
    expect(validateChannel(ch({ secret_env: 'DATABASE_URL' })).secret_env).toBe('envPrefix');
    expect(validateChannel(ch({ kind: 'slack', config: { mode: 'bot' }, secret_env: 'SLACK_BOT_TOKEN_OPS' })).channel).toBe('required');
    expect(validateChannel(ch({ kind: 'telegram', config: { chat_id: 'abc' }, secret_env: 'TELEGRAM_BOT_TOKEN_OPS' })).chat_id).toBe('chatId');
    // The instance bot: no secret, no chat id (set by /link); its own bot needs both.
    expect(validateChannel(ch({ kind: 'telegram', config: {}, secret_env: '' }))).toEqual({});
    expect(validateChannel(ch({ kind: 'telegram', config: {}, secret_env: 'TELEGRAM_BOT_TOKEN_OPS' })).chat_id).toBe('required');
    expect(validateChannel(ch({ kind: 'telegram', config: {}, secret_env: '' }), false, false).secret_env).toBe('noInstanceBot');
    expect(validateChannel(ch({ kind: 'webhook', secret_env: 'SLACK_X' })).secret_env).toBe('envPrefix');
    expect(validateChannel(ch({ kind: 'slack', config: { mode: 'webhook' }, secret_env: 'SLACK_BOT_TOKEN' })).secret_env).toBe('envInstance');
    expect(validateChannel(ch({ kind: 'a2a', config: { agent_card_url: 'https://agent.example.com' }, secret_env: '' }))).toEqual({});
    expect(validateChannel(ch({ kind: 'email', config: { to: ['a@b.co', 'nope'] }, secret_env: null })).to).toBe('email');
  });

  it('sends only the keys of the kind, never a secret_env for email', () => {
    expect(channelBody(ch({ kind: 'email', config: { to: ['a@b.co'], url: 'x' }, secret_env: 'X' }))).toEqual({ name: 'ops', kind: 'email', config: { to: ['a@b.co'] }, secret_env: null, enabled: true });
    expect(channelBody(ch({ kind: 'slack', config: { mode: 'webhook', channel: ' ' }, secret_env: ' SLACK_WEBHOOK_OPS ' })).config).toEqual({ mode: 'webhook' });
    expect(channelBody(ch({ config: { url: ' https://x.example/h ' } })).config).toEqual({ url: 'https://x.example/h', allow_private: false });
    // A2A keeps allow_private like webhooks (docs/alerts.md §4).
    expect(channelBody(ch({ kind: 'a2a', config: { agent_card_url: 'http://10.0.0.7:9000', allow_private: true } })).config).toEqual({ agent_card_url: 'http://10.0.0.7:9000', allow_private: true });
    expect(validateChannel(ch({ kind: 'a2a', config: { agent_card_url: 'http://10.0.0.7:9000', allow_private: true }, secret_env: '' }), true).agent_card_url).toBeUndefined();
    expect(validateChannel(ch({ kind: 'a2a', config: { agent_card_url: 'http://10.0.0.7:9000' }, secret_env: '' }), true).agent_card_url).toBe('https');
    expect(channelTarget('email', { to: ['a@b.co', 'c@d.co'] })).toBe('a@b.co, c@d.co');
    // The instance bot refuses a chat_id from the client.
    expect(channelBody(ch({ kind: 'telegram', config: { chat_id: '-100123' }, secret_env: '' })).config).toEqual({});
    expect(channelBody(ch({ kind: 'telegram', config: { chat_id: ' -100123 ' }, secret_env: 'TELEGRAM_BOT_TOKEN_OPS' })).config).toEqual({ chat_id: '-100123' });
    expect(channelBody(ch({ kind: 'email', config: { to: ['a@b.co'], lang: 'vi' }, secret_env: null })).config).toEqual({ to: ['a@b.co'], lang: 'vi' });
  });

  it('knows which channels need verification steps', () => {
    expect(needsTelegramLink({ kind: 'telegram', secret_env: null })).toBe(true);
    expect(needsTelegramLink({ kind: 'telegram', secret_env: 'TELEGRAM_BOT_TOKEN_OPS' })).toBe(false);
    expect(needsTelegramLink({ kind: 'slack', secret_env: null })).toBe(false);
    const addresses = [
      { address: 'a@b.co', confirmed: true, confirmed_at: 'x', sent_at: 'x' },
      { address: 'c@d.co', confirmed: false, confirmed_at: null, sent_at: 'x' },
    ];
    expect(unconfirmed({ kind: 'email', addresses }).map((x) => x.address)).toEqual(['c@d.co']);
    expect(unconfirmed({ kind: 'email', addresses: null })).toEqual([]);
  });
});

describe('notification stream', () => {
  it('parses event-stream chunks split anywhere, skipping heartbeats', () => {
    const p = new SseParser();
    const text = ': heartbeat\n\nevent: notification\ndata: {"id":"n1",\ndata: "title":"x"}\nid: 7\n\r\ndata: plain\r\n\r\n';
    const out = [];
    for (const ch of text) out.push(...p.push(ch));
    expect(out).toEqual([
      { event: 'notification', data: '{"id":"n1",\n"title":"x"}', id: '7' },
      { event: 'message', data: 'plain', id: '7' },
    ]);
  });

  it('backs off from 1 s to at most 30 s, with jitter', () => {
    expect(backoffDelay(0, () => 0.5)).toBe(1000);
    expect(backoffDelay(3, () => 0.5)).toBe(8000);
    expect(backoffDelay(20, () => 0.5)).toBe(30000);
    expect(backoffDelay(0, () => 0)).toBe(800);
    expect(backoffDelay(0, () => 1)).toBe(1200);
  });

  it('reads with a Bearer header, never a token in the URL', async () => {
    const seen: { url: string; auth: string | null }[] = [];
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('event: notification\ndata: {"id":"a","title":"T"}\n\n'));
        c.close();
      },
    });
    const fetchImpl = ((url: string, init: RequestInit) => {
      seen.push({ url, auth: new Headers(init.headers).get('Authorization') });
      return Promise.resolve(new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } }));
    }) as unknown as typeof fetch;
    const events: string[] = [];
    const end = await readStream({ url: '/v1/notifications/stream', token: 'tok', signal: new AbortController().signal, onEvent: (e) => events.push(e.data), fetchImpl });
    expect(end).toBe('closed');
    expect(events).toEqual(['{"id":"a","title":"T"}']);
    expect(seen).toEqual([{ url: '/v1/notifications/stream', auth: 'Bearer tok' }]);
    const gone = await readStream({ url: '/x', token: 't', signal: new AbortController().signal, onEvent: () => undefined, fetchImpl: () => Promise.resolve(new Response('', { status: 404 })) });
    expect(gone).toBe('unavailable');
  });

  it('applies notification and read events to the list', () => {
    const n = (id: string, read: string | null = null): AppNotification => ({ id, alert_id: 'a', title: id, body: '', severity: 'warning', read_at: read, created_at: '2026-11-04T08:00:00Z' });
    const items = [n('old')];
    const added = applyEvent(items, { event: 'notification', data: JSON.stringify(n('new')), id: null });
    expect(added?.items.map((x) => x.id)).toEqual(['new', 'old']);
    expect(added?.added).toBe(1);
    expect(applyEvent(added?.items ?? [], { event: 'notification', data: JSON.stringify(n('new')), id: null })).toBeNull();
    expect(applyEvent(items, { event: 'notification', data: 'not json', id: null })).toBeNull();
    const read = applyEvent(added?.items ?? [], { event: 'read', data: '{"ids":["new"]}', id: null });
    expect(read?.read).toEqual(['new']);
    expect(read?.items[0]?.read_at).not.toBeNull();
    expect(applyEvent(items, { event: 'read', data: '{"all":true}', id: null })?.read).toBe('all');
    expect(asNotification({ id: 'x', title: 't', severity: 'bogus' })?.severity).toBe('info');
    expect(asNotification({ id: 1 })).toBeNull();
    expect(nextUnread(3, { added: 1, read: 2 })).toBe(2);
    expect(nextUnread(1, { read: 5 })).toBe(0);
    expect(nextUnread(9, { all: true })).toBe(0);
  });
});

describe('personal notification settings', () => {
  it('offers only what the instance can deliver', () => {
    expect(availableKinds(null)).toEqual([]);
    expect(availableKinds({ telegram: { enabled: true, bot_username: 'gs_bot' }, slack_bot: false, smtp: true })).toEqual(['telegram', 'email']);
    expect(availableKinds({ telegram: { enabled: false }, slack_bot: true })).toEqual(['slack']);
  });

  it('fills missing prefs with defaults', () => {
    expect(fillPrefs(['telegram', 'email'], [{ channel_kind: 'telegram', enabled: true, min_severity: 'critical' }])).toEqual([
      { channel_kind: 'telegram', enabled: true, min_severity: 'critical' },
      { channel_kind: 'email', enabled: true, min_severity: 'info' },
    ]);
  });

  it('tells a verified link from a pending email address', () => {
    const links = [
      { kind: 'email' as const, address: 'old@acme.example', verified: true, verified_at: 'x' },
      { kind: 'email' as const, address: 'new@acme.example', verified: false, verified_at: null, expires_at: 'y' },
      { kind: 'telegram' as const, address: 'chat', verified_at: 'x' },
    ];
    expect(activeLink(links, 'email')?.address).toBe('old@acme.example');
    expect(pendingEmail(links)?.address).toBe('new@acme.example');
    // Older servers send no verified flag: the link counts.
    expect(activeLink(links, 'telegram')?.address).toBe('chat');
    expect(activeLink(links.slice(1, 2), 'email')).toBeNull();
  });

  it('reads group members in either shape', () => {
    expect(groupMemberIds({ id: 'g', name: 'n', description: null, user_ids: ['a'] })).toEqual(['a']);
    expect(groupMemberIds({ id: 'g', name: 'n', description: null, members: [{ user_id: 'b' }] })).toEqual(['b']);
    expect(groupMemberIds({ id: 'g', name: 'n', description: null })).toBeNull();
    expect(groupMemberCount({ id: 'g', name: 'n', description: null, member_count: 4 })).toBe(4);
  });
});

describe('alerts navigation and strings', () => {
  it('has the five alert pages and SIEM export under an Alerts group, at their contract paths', () => {
    const group = NAV.find((g) => g.id === 'alerts');
    expect(group?.items.map((i) => i.route)).toEqual(['alert-rules', 'alert-channels', 'alert-groups', 'alert-history', 'alert-deliveries', 'siem-export']);
    expect(PATHS['siem-export']).toBe('alerts/siem');
    // The webhook payload links to /ui/alerts/history?id=…
    expect(PATHS['alert-history']).toBe('alerts/history');
    expect(resolve('/ui/alerts/history', '?id=x', '', '/ui').route).toBe('alert-history');
    expect(resolve('/ui/alerts', '', '', '/ui').redirect).toBe('/ui/alerts/rules');
  });

  it('translates every alerts string into Vietnamese', () => {
    const keys = Object.keys(en).filter((k) => /^(alerts|bell|notif|nav\.alert|navg\.alerts)/.test(k)) as (keyof typeof en)[];
    expect(keys.length).toBeGreaterThan(200);
    const same = keys.filter((k) => viMessages[k] === en[k] && !/^alerts\.(kind|rule\.secondsIs)/.test(k) && !/^(alerts\.channel\.(secret|slackWebhook|slackBot))$/.test(k));
    expect(same).toEqual([]);
    // Placeholders match.
    for (const k of keys) {
      const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join();
      expect(ph(viMessages[k]), k).toBe(ph(en[k]));
    }
  });
});
