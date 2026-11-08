// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Pure helpers of the alert pages: defaults, validation, request bodies.

import { ROLES } from '../types';
import { ConditionParseError, parseAlertCondition } from './condition';
import { GROUP_BY_KEYS, type AlertRule, type AlertRuleInput, type ChannelInput, type ChannelKind, type QuietHours, type Severity } from './types';

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export function newRule(): AlertRuleInput {
  return {
    name: '',
    enabled: true,
    event_types: ['detection.blocked'],
    condition: '',
    threshold: 1,
    window_seconds: 300,
    severity: 'warning',
    throttle_seconds: 900,
    group_by: [],
    quiet_hours: null,
    auto_resolve: false,
    recipients: { user_ids: [], group_ids: [], roles: [] },
    channel_ids: [],
  };
}

export function defaultQuietHours(tz: string): QuietHours {
  return { tz, start: '22:00', end: '07:00', mode: 'suppress', critical_bypass: true };
}

/** A rule as the server sent it, with every field present. */
export function ruleInput(r: Partial<AlertRule>): AlertRuleInput {
  const d = newRule();
  return {
    name: r.name ?? d.name,
    enabled: r.enabled ?? d.enabled,
    event_types: Array.isArray(r.event_types) ? r.event_types : d.event_types,
    condition: r.condition ?? '',
    threshold: r.threshold ?? d.threshold,
    window_seconds: r.window_seconds ?? d.window_seconds,
    severity: r.severity ?? d.severity,
    throttle_seconds: r.throttle_seconds ?? d.throttle_seconds,
    group_by: Array.isArray(r.group_by) ? r.group_by : [],
    quiet_hours: r.quiet_hours ?? null,
    auto_resolve: r.auto_resolve ?? false,
    recipients: {
      user_ids: r.recipients?.user_ids ?? [],
      group_ids: r.recipients?.group_ids ?? [],
      roles: r.recipients?.roles ?? [],
    },
    channel_ids: Array.isArray(r.channel_ids) ? r.channel_ids : [],
  };
}

export type RuleErrors = Partial<Record<'name' | 'event_types' | 'condition' | 'threshold' | 'window_seconds' | 'throttle_seconds' | 'quiet_hours' | 'recipients', string>>;

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

/** Message keys (alerts.err.*) by field; empty when the rule can be saved. */
export function validateRule(r: AlertRuleInput): RuleErrors {
  const e: RuleErrors = {};
  if (r.name.trim() === '') e.name = 'required';
  else if (r.name.length > 120) e.name = 'tooLong';
  if (r.event_types.length === 0) e.event_types = 'eventTypes';
  if (!Number.isInteger(r.threshold) || r.threshold < 1) e.threshold = 'threshold';
  if (!Number.isInteger(r.window_seconds) || r.window_seconds < 60 || r.window_seconds > 86400) e.window_seconds = 'window';
  if (!Number.isInteger(r.throttle_seconds) || r.throttle_seconds < 0 || r.throttle_seconds > 604800) e.throttle_seconds = 'throttle';
  if (r.quiet_hours) {
    const q = r.quiet_hours;
    if (!q.tz.trim() || !HHMM.test(q.start) || !HHMM.test(q.end) || q.start === q.end) e.quiet_hours = 'quietHours';
  }
  try {
    parseAlertCondition(r.condition);
  } catch (err) {
    e.condition = err instanceof ConditionParseError ? err.message : String(err);
  }
  const rc = r.recipients;
  if (rc.user_ids.length + rc.group_ids.length + rc.roles.length + r.channel_ids.length === 0) e.recipients = 'recipients';
  return e;
}

/** The body of POST/PATCH: trimmed, group_by and roles in contract order. */
export function ruleBody(r: AlertRuleInput): AlertRuleInput {
  return {
    ...r,
    name: r.name.trim(),
    condition: r.condition.trim(),
    group_by: GROUP_BY_KEYS.filter((k) => r.group_by.includes(k)),
    recipients: { ...r.recipients, roles: ROLES.filter((x) => r.recipients.roles.includes(x)) },
  };
}

// ── Channels ───────────────────────────────────────────────────────────────

/** Contract §4: the shape and the prefixes an env name may have. */
export const ENV_NAME = /^[A-Z][A-Z0-9_]{2,63}$/;
export const ENV_PREFIXES = ['GUARDSPEC_ALERT_', 'TELEGRAM_BOT_TOKEN_', 'SLACK_', 'TEAMS_', 'WEBHOOK_SECRET_', 'A2A_', 'PAGERDUTY_', 'OPSGENIE_'] as const;

/** The suggested variable name per kind (helper text and placeholder). */
export function envExample(kind: ChannelKind, slackMode: 'bot' | 'webhook' = 'bot'): string {
  switch (kind) {
    case 'telegram':
      return 'TELEGRAM_BOT_TOKEN_OPS';
    case 'slack':
      return slackMode === 'bot' ? 'SLACK_BOT_TOKEN_OPS' : 'SLACK_WEBHOOK_OPS';
    case 'teams':
      return 'TEAMS_WEBHOOK_OPS';
    case 'webhook':
      return 'WEBHOOK_SECRET_SIEM';
    case 'a2a':
      return 'A2A_TOKEN_TRIAGE';
    case 'email':
      return '';
    case 'pagerduty':
      return 'PAGERDUTY_ROUTING_KEY_SEC';
    case 'opsgenie':
      return 'OPSGENIE_API_KEY_SEC';
  }
}

/** The prefix a kind's variable must have (or GUARDSPEC_ALERT_, docs/alerts.md §4). */
export const KIND_PREFIX: Record<Exclude<ChannelKind, 'email'>, string> = {
  telegram: 'TELEGRAM_BOT_TOKEN_',
  slack: 'SLACK_',
  teams: 'TEAMS_',
  webhook: 'WEBHOOK_SECRET_',
  a2a: 'A2A_',
  pagerduty: 'PAGERDUTY_',
  opsgenie: 'OPSGENIE_',
};
/** The instance tokens, never usable by a channel. */
const INSTANCE_TOKENS = ['TELEGRAM_BOT_TOKEN', 'SLACK_BOT_TOKEN'];

/** The prefixes a variable of this kind may have. */
export function kindPrefixes(kind: ChannelKind): string[] {
  return kind === 'email' ? [] : [KIND_PREFIX[kind], 'GUARDSPEC_ALERT_'];
}

/**
 * Whether name can be a channel secret: the shape, then the prefix of the
 * kind (any allowed prefix without a kind). The server also checks that the
 * operator bound it to this kind and org in ALERTS_SECRET_ORGS.
 */
export function envNameProblem(name: string, kind?: ChannelKind): 'format' | 'prefix' | 'instance' | null {
  if (!ENV_NAME.test(name)) return 'format';
  if (INSTANCE_TOKENS.includes(name)) return 'instance';
  const prefixes = kind ? kindPrefixes(kind) : [...ENV_PREFIXES];
  if (!prefixes.some((p) => name.startsWith(p))) return 'prefix';
  return null;
}

/**
 * Kinds whose secret is required. Email has none; A2A only if its card asks;
 * Telegram without one uses the instance bot (when the instance has one).
 */
export function secretRequired(kind: ChannelKind, instanceTelegram = true): boolean {
  if (kind === 'telegram') return !instanceTelegram;
  return kind === 'slack' || kind === 'teams' || kind === 'webhook' || kind === 'pagerduty' || kind === 'opsgenie';
}

/** A Telegram channel on the instance bot (no secret of its own): verified with /link, no chat_id from the client. */
export function onInstanceBot(c: { kind: ChannelKind; secret_env: string | null }): boolean {
  return c.kind === 'telegram' && (c.secret_env ?? '').trim() === '';
}

export type ChannelErrors = Partial<Record<'name' | 'secret_env' | 'url' | 'agent_card_url' | 'to' | 'chat_id' | 'channel', string>>;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function httpsUrl(s: string, allowHttp: boolean): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || (allowHttp && u.protocol === 'http:');
  } catch {
    return false;
  }
}

export function validateChannel(c: ChannelInput, allowPrivate = false, instanceTelegram = true): ChannelErrors {
  const e: ChannelErrors = {};
  if (c.name.trim() === '') e.name = 'required';
  const env = c.secret_env?.trim() ?? '';
  if (c.kind !== 'email') {
    if (env === '' && secretRequired(c.kind, instanceTelegram)) e.secret_env = c.kind === 'telegram' ? 'noInstanceBot' : 'required';
    else if (env !== '') {
      const p = envNameProblem(env, c.kind);
      if (p) e.secret_env = p === 'format' ? 'envFormat' : p === 'instance' ? 'envInstance' : 'envPrefix';
    }
  }
  const cfg = c.config;
  const str = (k: string) => (typeof cfg[k] === 'string' ? cfg[k].trim() : '');
  switch (c.kind) {
    case 'telegram':
      // Its own bot names the chat; the instance bot gets it from /link.
      if (env !== '') {
        if (!str('chat_id')) e.chat_id = 'required';
        else if (!/^-?\d+$|^@\w{4,}$/.test(str('chat_id'))) e.chat_id = 'chatId';
      }
      break;
    case 'slack':
      if (cfg.mode === 'bot' && !str('channel')) e.channel = 'required';
      break;
    case 'webhook':
      if (!httpsUrl(str('url'), allowPrivate && cfg.allow_private === true)) e.url = 'https';
      break;
    case 'a2a':
      if (!httpsUrl(str('agent_card_url'), allowPrivate && cfg.allow_private === true)) e.agent_card_url = 'https';
      break;
    case 'email': {
      const to = Array.isArray(cfg.to) ? (cfg.to as string[]) : [];
      if (to.length === 0) e.to = 'required';
      else if (to.some((x) => !EMAIL.test(x))) e.to = 'email';
      break;
    }
    case 'teams':
      break;
    case 'pagerduty':
    case 'opsgenie':
      if (cfg.region !== undefined && cfg.region !== 'us' && cfg.region !== 'eu') e.region = 'region';
      break;
  }
  return e;
}

/** The config a kind starts with. */
export function defaultConfig(kind: ChannelKind): Record<string, unknown> {
  switch (kind) {
    case 'slack':
      return { mode: 'webhook' };
    case 'webhook':
      return { url: '', allow_private: false };
    case 'a2a':
      return { agent_card_url: '', allow_private: false };
    case 'email':
      return { to: [] };
    case 'pagerduty':
    case 'opsgenie':
      return { region: 'us' };
    default:
      return {};
  }
}

/** Only the keys of the kind, trimmed; empty optional values left out. */
export function channelBody(c: ChannelInput): ChannelInput {
  const cfg = c.config;
  const s = (k: string) => (typeof cfg[k] === 'string' ? cfg[k].trim() : '');
  let config: Record<string, unknown> = {};
  switch (c.kind) {
    case 'telegram':
      // The instance bot refuses a chat_id from the client (400): /link sets it.
      config = onInstanceBot(c) ? {} : { chat_id: s('chat_id') };
      break;
    case 'slack':
      config = cfg.mode === 'bot' ? { mode: 'bot', channel: s('channel') } : { mode: 'webhook', ...(s('channel') ? { channel: s('channel') } : {}) };
      break;
    case 'webhook':
      config = { url: s('url'), allow_private: cfg.allow_private === true };
      break;
    case 'a2a':
      config = { agent_card_url: s('agent_card_url'), allow_private: cfg.allow_private === true };
      break;
    case 'email':
      config = { to: Array.isArray(cfg.to) ? (cfg.to as string[]) : [], ...(cfg.lang === 'en' || cfg.lang === 'vi' ? { lang: cfg.lang } : {}) };
      break;
    case 'teams':
      config = {};
      break;
    case 'pagerduty':
    case 'opsgenie':
      config = { region: cfg.region === 'eu' ? 'eu' : 'us' };
  }
  const env = c.secret_env?.trim() ?? '';
  return { name: c.name.trim(), kind: c.kind, config, secret_env: c.kind === 'email' || env === '' ? null : env, enabled: c.enabled };
}

/** A one-line description of where a channel sends (no secrets: config is non-secret). */
export function channelTarget(kind: ChannelKind, config: Record<string, unknown>): string {
  const s = (k: string) => (typeof config[k] === 'string' ? config[k] : '');
  switch (kind) {
    case 'telegram':
      return s('chat_id');
    case 'slack':
      return s('channel');
    case 'webhook':
      return s('url');
    case 'a2a':
      return s('agent_card_url');
    case 'email':
      return Array.isArray(config.to) ? (config.to as string[]).join(', ') : '';
    case 'teams':
      return '';
    case 'pagerduty':
      return `events api (${config.region === 'eu' ? 'eu' : 'us'})`;
    case 'opsgenie':
      return `alert api (${config.region === 'eu' ? 'eu' : 'us'})`;
  }
}

/** "5 min", "1 h 30 min", "1 day" (short, both languages use the same units). */
export function formatSeconds(s: number): string {
  if (s < 60) return `${s} s`;
  if (s % 86400 === 0) return `${s / 86400} d`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return [h ? `${h} h` : '', m ? `${m} min` : ''].filter(Boolean).join(' ') || `${s} s`;
}

/** Unread count after events: a new unread notification adds one; reads subtract. */
export function nextUnread(count: number, change: { added?: number; read?: number; all?: boolean }): number {
  if (change.all) return 0;
  return Math.max(0, count + (change.added ?? 0) - (change.read ?? 0));
}
