// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Real-time alerts and notifications (alerts contract RF-35448968).

import type { Role, UUID } from '../types';

export const SEVERITIES = ['info', 'warning', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Event types (contract §1), by source. */
export const EVENT_TYPE_GROUPS = [
  { id: 'detection', types: ['detection.blocked', 'detection.flagged'] },
  { id: 'upstream', types: ['upstream.error'] },
  { id: 'security', types: ['security.login_failed', 'security.mfa_locked', 'security.role_changed', 'security.owner_added', 'security.sso_changed'] },
  { id: 'config', types: ['config.policy_changed', 'config.upstream_changed'] },
  { id: 'test', types: ['alert.test'] },
] as const;
export const EVENT_TYPES: readonly string[] = EVENT_TYPE_GROUPS.flatMap((g) => g.types);

/** The dedupe keys a rule may group by (contract §2). */
export const GROUP_BY_KEYS = ['project_id', 'attrs.category', 'attrs.upstream_id'] as const;

export interface QuietHours {
  tz: string;
  start: string;
  end: string;
  mode: 'suppress' | 'delay';
  critical_bypass: boolean;
}

export interface Recipients {
  user_ids: UUID[];
  group_ids: UUID[];
  roles: Role[];
}

export interface AlertRule {
  id: UUID;
  name: string;
  enabled: boolean;
  event_types: string[];
  condition: string;
  threshold: number;
  window_seconds: number;
  severity: Severity;
  throttle_seconds: number;
  group_by: string[];
  quiet_hours: QuietHours | null;
  auto_resolve: boolean;
  /** Possibly partial from the server: ruleInput fills it in. */
  recipients?: Partial<Recipients> | null;
  channel_ids?: UUID[] | null;
  created_by?: UUID | null;
  created_at?: string;
  updated_at?: string;
}

export type AlertRuleInput = Omit<AlertRule, 'id' | 'created_by' | 'created_at' | 'updated_at' | 'recipients' | 'channel_ids'> & {
  recipients: Recipients;
  channel_ids: UUID[];
};

export const CHANNEL_KINDS = ['telegram', 'slack', 'teams', 'webhook', 'a2a', 'email', 'pagerduty', 'opsgenie'] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

export interface NotificationChannel {
  id: UUID;
  name: string;
  kind: ChannelKind;
  config?: Record<string, unknown> | null;
  secret_env: string | null;
  /** Whether the named variable is set on the server; never the value. */
  secret_set?: boolean;
  enabled: boolean;
  /**
   * Telegram on the instance bot is verified once a group sent the /link
   * command; email once an address confirmed; other kinds always (docs/alerts.md §4).
   */
  verified?: boolean;
  verified_at?: string | null;
  /** Email: the double opt-in state of each address of config.to. */
  addresses?: EmailAddressState[] | null;
  created_at?: string;
  updated_at?: string;
}

export interface EmailAddressState {
  address: string;
  confirmed: boolean;
  confirmed_at: string | null;
  sent_at: string | null;
}

/** POST /notification-channels/:id/telegram-link. */
export interface TelegramChannelLink {
  code: string;
  /** "/link@<bot> <code>", to send in the group. */
  command: string;
  bot_username: string;
  expires_at: string;
}

export interface ChannelInput {
  name: string;
  kind: ChannelKind;
  config: Record<string, unknown>;
  secret_env: string | null;
  enabled: boolean;
}

export interface ChannelTest {
  ok: boolean;
  status?: number | null;
  latency_ms?: number | null;
  error?: string | null;
}

export interface UserGroup {
  id: UUID;
  name: string;
  description: string | null;
  /** Member ids, when the server lists them (GET /:id; some lists too). */
  user_ids?: UUID[];
  /** Or member objects. */
  members?: { user_id: UUID; email?: string; display_name?: string | null }[];
  member_count?: number;
}

export type AlertState = 'firing' | 'resolved';

export interface Alert {
  id: UUID;
  rule_id: UUID;
  rule_name?: string;
  dedupe_key: string;
  state: AlertState;
  severity: Severity;
  first_at: string;
  last_at: string;
  count: number;
  resolved_at: string | null;
  sample_event_ids?: UUID[] | null;
  /** Detail only, when the server includes them. */
  samples?: { event_id?: UUID; id?: UUID; type: string; occurred_at: string; attrs?: Record<string, unknown> }[];
  project_id?: UUID | null;
  group?: Record<string, string>;
}

export const DELIVERY_STATES = ['pending', 'sending', 'sent', 'failed', 'dead'] as const;
export type DeliveryState = (typeof DELIVERY_STATES)[number];

/** A notification_outbox row (contract §5). */
export interface Delivery {
  id: UUID;
  alert_id: UUID;
  rule_id?: UUID | null;
  rule_name?: string | null;
  channel_kind: ChannelKind | 'in_app';
  channel_id: UUID | null;
  channel_name?: string | null;
  user_id: UUID | null;
  target: string | null;
  state: DeliveryState;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  created_at: string;
  sent_at: string | null;
}

/** An in-app notification. */
export interface AppNotification {
  id: UUID;
  alert_id: UUID | null;
  title: string;
  body: string;
  severity: Severity;
  read_at: string | null;
  created_at: string;
}

export const PERSONAL_KINDS = ['telegram', 'slack', 'email'] as const;
export type PersonalKind = (typeof PERSONAL_KINDS)[number];

export interface ChannelLink {
  kind: PersonalKind;
  address: string;
  /** false: a personal email address waiting for its code (with expires_at). */
  verified?: boolean;
  verified_at: string | null;
  expires_at?: string | null;
  created_at?: string;
}

/** PUT /v1/me/channel-links/email: 202 while the code is out. */
export interface EmailLinkPending {
  kind?: 'email';
  address?: string;
  verified: false;
  expires_at: string;
}

export interface NotificationPref {
  channel_kind: PersonalKind;
  enabled: boolean;
  min_severity: Severity;
}

export interface TelegramStart {
  code: string;
  deep_link: string;
  expires_at: string;
}

export interface AlertCapabilities {
  telegram?: { enabled?: boolean; bot_username?: string | null } | null;
  slack_bot?: boolean;
  smtp?: boolean;
  a2a?: boolean;
  webhook?: boolean;
  teams?: boolean;
  /** Per org (GET ?org_id=): the operator listed it in ALERTS_PRIVATE_ORGS. */
  allow_private_urls?: boolean;
  /** SMTP is set: shared and personal addresses can be confirmed. */
  email_confirmation?: boolean;
  /** Emails one org may send per 24 hours. */
  email_daily_cap?: number;
}
