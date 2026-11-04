// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The alerts contract (RF-35448968) in the in-memory control plane: rules,
// channels, groups, history, delivery log, personal links and preferences,
// in-app notifications and their stream.
//
// The stream (GET /v1/notifications/stream) cannot stay open through
// page.route: each request waits up to STREAM_HOLD_MS for queued events
// (state.streamQueue, filled by "Send test" or by a test), answers them as
// text/event-stream and ends; the UI then reconnects, as it does after a
// dropped connection.

import type { Page, Route } from '@playwright/test';
import { ConditionParseError, parseAlertCondition } from '../src/alerts/condition';
import type {
  Alert,
  AlertCapabilities,
  AlertRule,
  AppNotification,
  ChannelLink,
  Delivery,
  NotificationChannel,
  NotificationPref,
  UserGroup,
} from '../src/alerts/types';
import type { Member, Role } from '../src/types';

export const STREAM_HOLD_MS = 6000;
export const TELEGRAM_CODE = 'GS-4F7K2Q';
export const TELEGRAM_BOT = 'guardspec_alerts_bot';
export const CHANNEL_LINK_CODE = 'k7Qp2Z';
export const EMAIL_CODE = '482913';
export const LINKED_GROUP_CHAT = '-1009876543210';

export interface AlertsState {
  rules: AlertRule[];
  channels: NotificationChannel[];
  /** Group with its member ids. */
  groups: (UserGroup & { user_ids: string[] })[];
  alerts: Alert[];
  deliveries: Delivery[];
  notifications: AppNotification[];
  links: ChannelLink[];
  prefs: NotificationPref[];
  caps: AlertCapabilities;
  /** Events the next stream response sends ({event, data}). */
  streamQueue: { event: string; data: unknown }[];
  /** Stream requests seen, with their Authorization header and URL. */
  streams: { auth: string | null; url: string }[];
  /** Telegram linking: polls of GET /me/channel-links since /start. */
  telegramPending: number | null;
  /** Env variables the mock control plane "has" (secret_set). */
  env: Set<string>;
  /** ALERTS_SECRET_ORGS of the mock: variable name to the one kind it is bound to (for this org). */
  secretOrgs: Record<string, string>;
  /** Telegram group verification: polls of GET /notification-channels/:id per channel since /telegram-link. */
  channelLinkPending: Record<string, number>;
  /** The org is in ALERTS_PRIVATE_ORGS (capabilities with ?org_id=). */
  privateOrg: boolean;
  /** Capabilities requests, with their org_id. */
  capsCalls: (string | null)[];
  /** When the last personal email code was sent (429 within a minute). */
  emailCodeAt: number | null;
}

const T = (minAgo: number) => new Date(Date.parse('2026-11-04T08:00:00Z') - minAgo * 60_000).toISOString();
let seq = 0;
const id = (prefix: string) => `${prefix}-${String(++seq).padStart(4, '0')}-4000-8000-000000000000`;

export function seedAlerts(members: Member[], rich: boolean): AlertsState {
  seq = 0;
  const env = new Set(['SLACK_WEBHOOK_SECOPS', 'WEBHOOK_SECRET_SIEM', 'TELEGRAM_BOT_TOKEN_ONCALL']);
  const channels: NotificationChannel[] = [
    { id: id('ch'), name: 'secops-slack', kind: 'slack', config: { mode: 'webhook', channel: '#secops-alerts' }, secret_env: 'SLACK_WEBHOOK_SECOPS', enabled: true, created_at: T(9000) },
    { id: id('ch'), name: 'siem-webhook', kind: 'webhook', config: { url: 'https://siem.acme.example/hooks/guardspec', allow_private: false }, secret_env: 'WEBHOOK_SECRET_SIEM', enabled: true, created_at: T(8000) },
    { id: id('ch'), name: 'oncall-telegram', kind: 'telegram', config: { chat_id: '-1001234567890' }, secret_env: 'TELEGRAM_BOT_TOKEN_ONCALL', enabled: true, verified: true, verified_at: T(7000), created_at: T(7000) },
    { id: id('ch'), name: 'it-teams', kind: 'teams', config: {}, secret_env: 'TEAMS_WEBHOOK_IT', enabled: false, created_at: T(6000) },
    {
      id: id('ch'),
      name: 'security-mailbox',
      kind: 'email',
      config: { to: ['security@acme.example', 'ciso@acme.example'] },
      secret_env: null,
      enabled: true,
      verified: true,
      verified_at: T(4900),
      addresses: [
        { address: 'security@acme.example', confirmed: true, confirmed_at: T(4900), sent_at: T(5000) },
        { address: 'ciso@acme.example', confirmed: false, confirmed_at: null, sent_at: T(5000) },
      ],
      created_at: T(5000),
    },
    { id: id('ch'), name: 'soc-group-telegram', kind: 'telegram', config: {}, secret_env: null, enabled: true, verified: false, verified_at: null, created_at: T(4000) },
  ];
  const m = (i: number) => members[i]?.user_id ?? members[0]?.user_id ?? 'u';
  const groups = [
    { id: id('grp'), name: 'Security on-call', description: 'Paged for critical detections and lockouts', user_ids: [m(0), m(1), m(3)] },
    { id: id('grp'), name: 'Platform team', description: 'Model provider outages and config changes', user_ids: [m(2)] },
  ];
  const ch = (i: number) => channels[i]?.id ?? '';
  const grp = (i: number) => groups[i]?.id ?? '';
  const rules: AlertRule[] = [
    {
      id: id('rule'),
      name: 'Jailbreak burst',
      enabled: true,
      event_types: ['detection.blocked', 'detection.flagged'],
      condition: '"jailbreak" in attrs.categories && attrs.score >= 0.9',
      threshold: 5,
      window_seconds: 300,
      severity: 'critical',
      throttle_seconds: 900,
      group_by: ['project_id'],
      quiet_hours: null,
      auto_resolve: true,
      recipients: { user_ids: [], group_ids: [grp(0)], roles: ['owner'] },
      channel_ids: [ch(0), ch(1)],
      created_at: T(8000),
      updated_at: T(120),
    },
    {
      id: id('rule'),
      name: 'Model provider errors',
      enabled: true,
      event_types: ['upstream.error'],
      condition: 'attrs.error_kind in ["timeout", "5xx"]',
      threshold: 10,
      window_seconds: 600,
      severity: 'warning',
      throttle_seconds: 1800,
      group_by: ['attrs.upstream_id'],
      quiet_hours: { tz: 'Asia/Ho_Chi_Minh', start: '22:00', end: '07:00', mode: 'delay', critical_bypass: true },
      auto_resolve: true,
      recipients: { user_ids: [], group_ids: [grp(1)], roles: [] },
      channel_ids: [ch(2)],
      created_at: T(7000),
      updated_at: T(2000),
    },
    {
      id: id('rule'),
      name: 'Failed sign-ins',
      enabled: false,
      event_types: ['security.login_failed', 'security.mfa_locked'],
      condition: '',
      threshold: 20,
      window_seconds: 900,
      severity: 'warning',
      throttle_seconds: 3600,
      group_by: [],
      quiet_hours: null,
      auto_resolve: false,
      recipients: { user_ids: [m(0)], group_ids: [], roles: ['admin'] },
      channel_ids: [ch(4)],
      created_at: T(6000),
      updated_at: T(6000),
    },
  ];
  const r0 = rules[0];
  const r1 = rules[1];
  const nAlerts = rich ? 34 : 6;
  const alerts: Alert[] = Array.from({ length: nAlerts }, (_, i) => {
    const r = i % 3 === 1 ? r1 : r0;
    const firing = i < 2;
    return {
      id: id('alert'),
      rule_id: r?.id ?? '',
      dedupe_key: r === r1 ? `attrs.upstream_id=${i % 2 ? 'main' : 'azure-eastasia-production-gpt4o'}` : `project_id=${i % 2 ? 'billing' : 'support'}`,
      state: firing ? 'firing' : 'resolved',
      severity: r?.severity ?? 'warning',
      first_at: T(30 + i * 95),
      last_at: T(5 + i * 95),
      count: 5 + ((i * 7) % 23),
      resolved_at: firing ? null : T(i * 95),
      sample_event_ids: [id('ev'), id('ev')],
      samples:
        r === r1
          ? [{ event_id: id('ev'), type: 'upstream.error', occurred_at: T(6 + i * 95), attrs: { upstream_id: 'main', status: 504, error_kind: 'timeout' } }]
          : [
              { event_id: id('ev'), type: 'detection.blocked', occurred_at: T(6 + i * 95), attrs: { request_id: 'req_8f2a', categories: ['jailbreak'], score: 0.97, layer: 'l2', decision: 'block', model: 'gpt-4o' } },
              { event_id: id('ev'), type: 'detection.flagged', occurred_at: T(9 + i * 95), attrs: { request_id: 'req_77c1', categories: ['jailbreak', 'exfiltration'], score: 0.91, layer: 'l1', decision: 'log', model: 'gpt-4o-mini' } },
            ],
    };
  });
  const states: Delivery['state'][] = ['sent', 'sent', 'failed', 'dead', 'sent', 'pending', 'sent', 'sending'];
  const errors: Record<string, string> = {
    failed: 'HTTP 503 from siem.acme.example (path redacted); retrying with backoff',
    dead: 'HTTP 404 from hooks.slack.com/services/[redacted]: channel_not_found — permanent, gave up after 1 attempt',
  };
  const nDel = rich ? 48 : 8;
  const deliveries: Delivery[] = Array.from({ length: nDel }, (_, i) => {
    const s = states[i % states.length] ?? 'sent';
    const c = channels[i % 3];
    const a = alerts[i % alerts.length];
    return {
      id: id('del'),
      alert_id: a?.id ?? '',
      rule_id: a?.rule_id ?? null,
      channel_kind: c?.kind ?? 'webhook',
      channel_id: c?.id ?? null,
      channel_name: c?.name ?? null,
      user_id: null,
      target: c ? (c.kind === 'slack' ? '#secops-alerts' : c.kind === 'telegram' ? '-1001234567890' : 'https://siem.acme.example') : null,
      state: s,
      attempts: s === 'dead' ? 1 : s === 'failed' ? 3 : s === 'pending' ? 0 : 1,
      next_attempt_at: s === 'failed' ? T(-4) : s === 'pending' ? T(-1) : null,
      last_error: errors[s] ?? null,
      created_at: T(4 + i * 41),
      sent_at: s === 'sent' ? T(3 + i * 41) : null,
    };
  });
  const notifications: AppNotification[] = [
    { id: id('ntf'), alert_id: alerts[0]?.id ?? null, title: 'Jailbreak burst firing', body: '7 blocked or flagged jailbreak requests in 5 min · project billing', severity: 'critical', read_at: null, created_at: T(5) },
    { id: id('ntf'), alert_id: alerts[1]?.id ?? null, title: 'Model provider errors firing', body: '12 timeouts from main in 10 min', severity: 'warning', read_at: null, created_at: T(40) },
    { id: id('ntf'), alert_id: alerts[2]?.id ?? null, title: 'Jailbreak burst resolved', body: 'Back under 5 in 5 min · project support', severity: 'critical', read_at: T(100), created_at: T(190) },
  ];
  return {
    rules,
    channels,
    groups,
    alerts,
    deliveries,
    notifications,
    links: [],
    prefs: [{ channel_kind: 'email', enabled: true, min_severity: 'critical' }],
    caps: { telegram: { enabled: true, bot_username: TELEGRAM_BOT }, slack_bot: true, smtp: true, email_confirmation: true, email_daily_cap: 500, a2a: true, webhook: true, teams: true, allow_private_urls: false },
    streamQueue: [],
    streams: [],
    telegramPending: null,
    env,
    secretOrgs: { SLACK_WEBHOOK_SECOPS: 'slack', WEBHOOK_SECRET_SIEM: 'webhook', TELEGRAM_BOT_TOKEN_ONCALL: 'telegram', TEAMS_WEBHOOK_IT: 'teams', WEBHOOK_SECRET_SOC: 'webhook' },
    channelLinkPending: {},
    privateOrg: false,
    capsCalls: [],
    emailCodeAt: null,
  };
}

function withSecret(s: AlertsState, c: NotificationChannel): NotificationChannel {
  return { ...c, secret_set: c.secret_env ? s.env.has(c.secret_env) : false, verified: c.verified ?? true };
}

function page(items: unknown[], url: URL): unknown {
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit') ?? 50)));
  const cursor = url.searchParams.get('cursor');
  const start = cursor ? Number(Buffer.from(cursor, 'base64url').toString()) : 0;
  const slice = items.slice(start, start + limit);
  const next = start + limit < items.length ? Buffer.from(String(start + limit)).toString('base64url') : null;
  return { items: slice, next_cursor: next, total: items.length, total_capped: false };
}

const ENV = /^[A-Z][A-Z0-9_]{2,63}$/;
const KIND_PREFIX: Record<string, string> = { telegram: 'TELEGRAM_BOT_TOKEN_', slack: 'SLACK_', teams: 'TEAMS_', webhook: 'WEBHOOK_SECRET_', a2a: 'A2A_' };

/** docs/alerts.md §4: shape, the kind's prefix, and the ALERTS_SECRET_ORGS binding. */
function envRefused(s: AlertsState, kind: string, name: string | null | undefined): string | null {
  if (!name) return null;
  const prefix = KIND_PREFIX[kind] ?? '';
  if (!ENV.test(name) || name === 'TELEGRAM_BOT_TOKEN' || name === 'SLACK_BOT_TOKEN' || !(name.startsWith(prefix) || name.startsWith('GUARDSPEC_ALERT_'))) {
    return `secret_env ${name} is not allowed for a ${kind} channel: use a name starting with ${prefix} or GUARDSPEC_ALERT_`;
  }
  if (s.secretOrgs[name] !== kind) return `secret_env ${name} is not listed for ${kind} channels of this organization in ALERTS_SECRET_ORGS (${name}=${kind}:<org-id>)`;
  return null;
}

function sse(events: { event: string; data: unknown }[]): string {
  return ': connected\n\n' + events.map((e) => `event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`).join('');
}

/** A notification for a test alert, queued for the stream. */
export function pushNotification(s: AlertsState, n: Partial<AppNotification> & { title: string }): AppNotification {
  const full: AppNotification = { id: id('ntf'), alert_id: null, body: '', severity: 'info', read_at: null, created_at: new Date().toISOString(), ...n };
  s.notifications.unshift(full);
  s.streamQueue.push({ event: 'notification', data: full });
  return full;
}

type Json = (status: number, data?: unknown) => Promise<void>;

/**
 * Self-service endpoints (/notifications, /me/channel-links, /alerts/capabilities).
 * Returns true when it answered.
 */
export async function handleAlertsUser(page_: Page, route: Route, s: AlertsState, method: string, path: string, url: URL, body: unknown, json: Json, auth: string | null): Promise<boolean> {
  if (path === '/alerts/capabilities' && method === 'GET') {
    const orgId = url.searchParams.get('org_id');
    s.capsCalls.push(orgId);
    return json(200, { ...s.caps, allow_private_urls: orgId !== null && s.privateOrg }).then(() => true);
  }
  if (path === '/notifications/stream' && method === 'GET') {
    s.streams.push({ auth, url: url.toString() });
    const until = Date.now() + STREAM_HOLD_MS;
    while (s.streamQueue.length === 0 && Date.now() < until && !page_.isClosed()) await new Promise((r) => setTimeout(r, 100));
    const events = s.streamQueue.splice(0);
    try {
      await route.fulfill({ status: 200, headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' }, body: sse(events) });
    } catch {
      // The page went away while the stream was held.
    }
    return true;
  }
  if (path === '/notifications' && method === 'GET') {
    const unread = url.searchParams.get('unread') === '1';
    return json(200, page(s.notifications.filter((n) => !unread || !n.read_at), url)).then(() => true);
  }
  if (path === '/notifications/read' && method === 'POST') {
    const b = (body ?? {}) as { ids?: string[]; all?: boolean };
    const now = new Date().toISOString();
    for (const n of s.notifications) if (b.all || b.ids?.includes(n.id)) n.read_at ??= now;
    return json(204).then(() => true);
  }
  if (path === '/me/channel-links' && method === 'GET') {
    if (s.telegramPending !== null) {
      s.telegramPending += 1;
      // The user pressed Start in Telegram on the second poll.
      if (s.telegramPending >= 2) {
        s.links = [...s.links.filter((l) => l.kind !== 'telegram'), { kind: 'telegram', address: '@ada_admin (chat 551234987)', verified: true, verified_at: new Date().toISOString() }];
        s.telegramPending = null;
      }
    }
    return json(200, { items: s.links }).then(() => true);
  }
  if (path === '/me/channel-links/telegram/start' && method === 'POST') {
    if (!s.caps.telegram?.enabled) return json(404, { error: 'telegram is not configured' }).then(() => true);
    s.telegramPending = 0;
    return json(200, { code: TELEGRAM_CODE, deep_link: `https://t.me/${TELEGRAM_BOT}?start=${TELEGRAM_CODE}`, expires_at: new Date(Date.now() + 10 * 60_000).toISOString() }).then(() => true);
  }
  if (path === '/me/channel-links/slack' && method === 'POST') {
    const link: ChannelLink = { kind: 'slack', address: 'U07ADAADMIN', verified: true, verified_at: new Date().toISOString() };
    s.links = [...s.links.filter((l) => l.kind !== 'slack'), link];
    return json(200, link).then(() => true);
  }
  if (path === '/me/channel-links/email' && method === 'PUT') {
    const address = (body as { address?: string }).address ?? '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) return json(400, { error: 'address is not a valid email address' }).then(() => true);
    if (s.emailCodeAt !== null && Date.now() - s.emailCodeAt < 60_000) return json(429, { error: 'a code was sent less than a minute ago' }).then(() => true);
    s.emailCodeAt = Date.now();
    const pending: ChannelLink = { kind: 'email', address, verified: false, verified_at: null, expires_at: new Date(Date.now() + 30 * 60_000).toISOString() };
    s.links = [...s.links.filter((l) => !(l.kind === 'email' && l.verified === false)), pending];
    return json(202, { kind: 'email', address, verified: false, expires_at: pending.expires_at }).then(() => true);
  }
  if (path === '/me/channel-links/email/confirm' && method === 'POST') {
    const pending = s.links.find((l) => l.kind === 'email' && l.verified === false);
    if (!pending || (body as { code?: string }).code !== EMAIL_CODE) return json(400, { error: 'wrong, expired or used-up code' }).then(() => true);
    const link: ChannelLink = { kind: 'email', address: pending.address, verified: true, verified_at: new Date().toISOString() };
    s.links = [...s.links.filter((l) => l.kind !== 'email'), link];
    return json(200, link).then(() => true);
  }
  const mm = /^\/me\/channel-links\/([a-z]+)$/.exec(path);
  if (mm && method === 'DELETE') {
    s.links = s.links.filter((l) => l.kind !== mm[1]);
    return json(204).then(() => true);
  }
  return false;
}

/** Org endpoints (sub is the path after /organizations/:id). */
export async function handleAlertsOrg(s: AlertsState, members: Member[], role: Role, method: string, sub: string, url: URL, body: unknown, json: Json): Promise<boolean> {
  const done = (status: number, data?: unknown) => json(status, data).then(() => true);
  const admin = role === 'admin' || role === 'owner';
  const isWrite = method !== 'GET';
  const alertsPath = /^\/(alert-rules|notification-channels|user-groups|alerts|notification-deliveries)(\/|$)/.test(sub);
  if (alertsPath && isWrite && !admin) return done(403, { error: 'requires role admin' });
  if (sub.startsWith('/notification-deliveries') && !admin) return done(403, { error: 'requires role admin' });
  let m: RegExpExecArray | null;

  // Rules
  if (sub === '/alert-rules' && method === 'GET') return done(200, page(s.rules, url));
  const checkRule = (b: Partial<AlertRule>): string | null => {
    try {
      parseAlertCondition(b.condition ?? '');
    } catch (e) {
      return `condition: ${e instanceof ConditionParseError ? e.message : String(e)}`;
    }
    if (!b.name?.trim()) return 'name is required';
    return null;
  };
  if (sub === '/alert-rules' && method === 'POST') {
    const b = body as AlertRule;
    const err = checkRule(b);
    if (err) return done(400, { error: err });
    const r: AlertRule = { ...b, id: id('rule'), created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    s.rules.push(r);
    return done(201, r);
  }
  if ((m = /^\/alert-rules\/([^/]+)(\/test)?$/.exec(sub))) {
    const r = s.rules.find((x) => x.id === m?.[1]);
    if (!r) return done(404, { error: 'rule not found' });
    if (m[2] && method === 'POST') {
      const a: Alert = { id: id('alert'), rule_id: r.id, dedupe_key: '', state: 'firing', severity: r.severity, first_at: new Date().toISOString(), last_at: new Date().toISOString(), count: 1, resolved_at: null, sample_event_ids: [id('ev')], samples: [{ type: 'alert.test', occurred_at: new Date().toISOString(), attrs: { actor_id: members[0]?.user_id ?? '' } }] };
      s.alerts.unshift(a);
      pushNotification(s, { alert_id: a.id, title: `Test: ${r.name}`, body: 'A test alert sent from the admin UI', severity: r.severity });
      return done(200, { alert_id: a.id });
    }
    if (method === 'GET') return done(200, r);
    if (method === 'PATCH') {
      const b = body as Partial<AlertRule>;
      if ('condition' in b || 'name' in b) {
        const err = checkRule({ ...r, ...b });
        if (err) return done(400, { error: err });
      }
      Object.assign(r, b, { updated_at: new Date().toISOString() });
      return done(200, r);
    }
    if (method === 'DELETE') {
      s.rules = s.rules.filter((x) => x !== r);
      return done(204);
    }
  }

  // Channels
  if (sub === '/notification-channels' && method === 'GET') return done(200, page(s.channels.map((c) => withSecret(s, c)), url));
  if (sub === '/notification-channels' && method === 'POST') {
    const b = body as NotificationChannel;
    const refused = envRefused(s, b.kind, b.secret_env);
    if (refused) return done(400, { error: refused });
    if (b.kind === 'telegram' && !b.secret_env && b.config && 'chat_id' in b.config) return done(400, { error: 'chat_id: on the instance bot the chat is set by /link, not by the client' });
    if (s.channels.some((c) => c.name === b.name)) return done(409, { error: 'a channel with this name exists' });
    const now = new Date().toISOString();
    const instanceBot = b.kind === 'telegram' && !b.secret_env;
    const to = b.kind === 'email' && Array.isArray(b.config?.to) ? (b.config.to as string[]) : [];
    const c: NotificationChannel = {
      ...b,
      id: id('ch'),
      created_at: now,
      verified: !instanceBot && b.kind !== 'email',
      verified_at: instanceBot || b.kind === 'email' ? null : now,
      ...(b.kind === 'email' ? { addresses: to.map((address) => ({ address, confirmed: false, confirmed_at: null, sent_at: now })) } : {}),
    };
    s.channels.push(c);
    return done(201, withSecret(s, c));
  }
  if ((m = /^\/notification-channels\/([^/]+)(\/test|\/telegram-link|\/email-confirmations)?$/.exec(sub))) {
    const c = s.channels.find((x) => x.id === m?.[1]);
    if (!c) return done(404, { error: 'channel not found' });
    if (m[2] === '/telegram-link' && method === 'POST') {
      if (c.kind !== 'telegram' || c.secret_env) return done(400, { error: 'only telegram channels on the instance bot are linked' });
      s.channelLinkPending[c.id] = 0;
      return done(200, { code: CHANNEL_LINK_CODE, command: `/link@${TELEGRAM_BOT} ${CHANNEL_LINK_CODE}`, bot_username: TELEGRAM_BOT, expires_at: new Date(Date.now() + 10 * 60_000).toISOString() });
    }
    if (m[2] === '/email-confirmations' && method === 'POST') {
      if (c.kind !== 'email') return done(400, { error: 'not an email channel' });
      const now = new Date().toISOString();
      c.addresses = (c.addresses ?? []).map((x) => (x.confirmed ? x : { ...x, sent_at: now }));
      return done(200, withSecret(s, c));
    }
    if (m[2] === '/test' && method === 'POST') {
      if (c.verified === false) return done(200, { ok: false, status: null, latency_ms: null, error: 'not verified: send the /link command in the group first' });
      if (c.secret_env && !s.env.has(c.secret_env)) return done(200, { ok: false, status: null, latency_ms: null, error: `${c.secret_env} is not set on the control plane` });
      if (c.kind === 'webhook') return done(200, { ok: false, status: 502, latency_ms: 341, error: 'HTTP 502 from siem.acme.example (path redacted)' });
      return done(200, { ok: true, status: 200, latency_ms: c.kind === 'email' ? 912 : 183 });
    }
    if (method === 'GET') {
      const polls = s.channelLinkPending[c.id];
      if (polls !== undefined) {
        // Someone sent /link in the group by the second poll.
        s.channelLinkPending[c.id] = polls + 1;
        if (polls + 1 >= 2) {
          s.channelLinkPending = Object.fromEntries(Object.entries(s.channelLinkPending).filter(([k]) => k !== c.id));
          c.verified = true;
          c.verified_at = new Date().toISOString();
          c.config = { chat_id: LINKED_GROUP_CHAT };
        }
      }
      return done(200, withSecret(s, c));
    }
    if (method === 'PATCH') {
      const b = body as Partial<NotificationChannel>;
      const refused = envRefused(s, c.kind, b.secret_env);
      if (refused) return done(400, { error: refused });
      Object.assign(c, b);
      return done(200, withSecret(s, c));
    }
    if (method === 'DELETE') {
      s.channels = s.channels.filter((x) => x !== c);
      return done(204);
    }
  }

  // Groups
  if (sub === '/user-groups' && method === 'GET') return done(200, page(s.groups.map((g) => ({ id: g.id, name: g.name, description: g.description, member_count: g.user_ids.length })), url));
  if (sub === '/user-groups' && method === 'POST') {
    const b = body as { name: string; description: string | null };
    if (!b.name.trim()) return done(400, { error: 'name is required' });
    const g = { id: id('grp'), name: b.name, description: b.description, user_ids: [] as string[] };
    s.groups.push(g);
    return done(201, g);
  }
  if ((m = /^\/user-groups\/([^/]+)(\/members)?$/.exec(sub))) {
    const g = s.groups.find((x) => x.id === m?.[1]);
    if (!g) return done(404, { error: 'group not found' });
    if (m[2] && method === 'PUT') {
      const ids = (body as { user_ids: string[] }).user_ids;
      const outsider = ids.find((u) => !members.some((x) => x.user_id === u));
      if (outsider) return done(400, { error: `user ${outsider} is not a member of this organization` });
      g.user_ids = [...ids];
      return done(200, { user_ids: g.user_ids });
    }
    if (method === 'GET') return done(200, { ...g, members: g.user_ids.map((u) => ({ user_id: u })) });
    if (method === 'PATCH') {
      Object.assign(g, body as Partial<UserGroup>);
      return done(200, g);
    }
    if (method === 'DELETE') {
      s.groups = s.groups.filter((x) => x !== g);
      return done(204);
    }
  }

  // History and delivery log
  if (sub === '/alerts' && method === 'GET') {
    const st = url.searchParams.get('state');
    const rule = url.searchParams.get('rule_id');
    return done(200, page(s.alerts.filter((a) => (!st || a.state === st) && (!rule || a.rule_id === rule)).map(({ samples: _s, ...a }) => a), url));
  }
  if ((m = /^\/alerts\/([^/]+)$/.exec(sub)) && method === 'GET') {
    const a = s.alerts.find((x) => x.id === m?.[1]);
    return a ? done(200, a) : done(404, { error: 'alert not found' });
  }
  if (sub === '/notification-deliveries' && method === 'GET') {
    const st = url.searchParams.get('state');
    const kind = url.searchParams.get('channel_kind');
    const rule = url.searchParams.get('rule_id');
    return done(200, page(s.deliveries.filter((d) => (!st || d.state === st) && (!kind || d.channel_kind === kind) && (!rule || d.rule_id === rule)), url));
  }

  // Personal preferences in this org
  if (sub === '/me/notification-prefs' && method === 'GET') return done(200, s.prefs);
  if (sub === '/me/notification-prefs' && method === 'PUT') {
    s.prefs = body as NotificationPref[];
    return done(200, s.prefs);
  }
  return false;
}
