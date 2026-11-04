// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Calls of the alerts contract (§6) on the shared ApiClient: same Bearer
// token, same errors, same 401 handling.

import { listOf, type ApiClient, type ListQuery } from '../api';
import type { UUID } from '../types';
import type {
  Alert,
  AlertCapabilities,
  AlertRule,
  AlertRuleInput,
  AppNotification,
  ChannelInput,
  ChannelLink,
  ChannelTest,
  EmailLinkPending,
  NotificationChannel,
  NotificationPref,
  TelegramChannelLink,
  TelegramStart,
  UserGroup,
} from './types';

const enc = encodeURIComponent;
const org = (id: UUID) => `/organizations/${enc(id)}`;

export function alertsApi(api: ApiClient) {
  return {
    // Rules
    listRules: (orgId: UUID, q: ListQuery): Promise<unknown> => api.request('GET', `${org(orgId)}/alert-rules`, { query: q }),
    async allRules(orgId: UUID): Promise<AlertRule[]> {
      return listOf<AlertRule>(await api.request('GET', `${org(orgId)}/alert-rules`, { query: { limit: 200 } }));
    },
    createRule: (orgId: UUID, input: AlertRuleInput): Promise<AlertRule> => api.request('POST', `${org(orgId)}/alert-rules`, { body: input }),
    updateRule: (orgId: UUID, id: UUID, input: Partial<AlertRuleInput>): Promise<AlertRule> =>
      api.request('PATCH', `${org(orgId)}/alert-rules/${enc(id)}`, { body: input }),
    deleteRule: (orgId: UUID, id: UUID): Promise<void> => api.request('DELETE', `${org(orgId)}/alert-rules/${enc(id)}`),
    testRule: (orgId: UUID, id: UUID): Promise<{ alert_id?: UUID } | undefined> => api.request('POST', `${org(orgId)}/alert-rules/${enc(id)}/test`),

    // Channels
    listChannels: (orgId: UUID, q: ListQuery): Promise<unknown> => api.request('GET', `${org(orgId)}/notification-channels`, { query: q }),
    async allChannels(orgId: UUID): Promise<NotificationChannel[]> {
      return listOf<NotificationChannel>(await api.request('GET', `${org(orgId)}/notification-channels`, { query: { limit: 200 } }));
    },
    createChannel: (orgId: UUID, input: ChannelInput): Promise<NotificationChannel> => api.request('POST', `${org(orgId)}/notification-channels`, { body: input }),
    updateChannel: (orgId: UUID, id: UUID, input: Partial<ChannelInput>): Promise<NotificationChannel> =>
      api.request('PATCH', `${org(orgId)}/notification-channels/${enc(id)}`, { body: input }),
    deleteChannel: (orgId: UUID, id: UUID): Promise<void> => api.request('DELETE', `${org(orgId)}/notification-channels/${enc(id)}`),
    testChannel: (orgId: UUID, id: UUID): Promise<ChannelTest> => api.request('POST', `${org(orgId)}/notification-channels/${enc(id)}/test`),
    getChannel: (orgId: UUID, id: UUID): Promise<NotificationChannel> => api.request('GET', `${org(orgId)}/notification-channels/${enc(id)}`),
    /** Telegram on the instance bot: a one-time /link command for the group. */
    telegramChannelLink: (orgId: UUID, id: UUID): Promise<TelegramChannelLink> => api.request('POST', `${org(orgId)}/notification-channels/${enc(id)}/telegram-link`),
    /** Email: mails new confirmation links to the unconfirmed addresses; returns the channel. */
    resendEmailConfirmations: (orgId: UUID, id: UUID): Promise<NotificationChannel | undefined> =>
      api.request('POST', `${org(orgId)}/notification-channels/${enc(id)}/email-confirmations`),

    // Groups
    listGroups: (orgId: UUID, q: ListQuery): Promise<unknown> => api.request('GET', `${org(orgId)}/user-groups`, { query: q }),
    async allGroups(orgId: UUID): Promise<UserGroup[]> {
      return listOf<UserGroup>(await api.request('GET', `${org(orgId)}/user-groups`, { query: { limit: 200 } }));
    },
    getGroup: (orgId: UUID, id: UUID): Promise<UserGroup> => api.request('GET', `${org(orgId)}/user-groups/${enc(id)}`),
    createGroup: (orgId: UUID, input: { name: string; description: string | null }): Promise<UserGroup> =>
      api.request('POST', `${org(orgId)}/user-groups`, { body: input }),
    updateGroup: (orgId: UUID, id: UUID, input: { name?: string; description?: string | null }): Promise<UserGroup> =>
      api.request('PATCH', `${org(orgId)}/user-groups/${enc(id)}`, { body: input }),
    deleteGroup: (orgId: UUID, id: UUID): Promise<void> => api.request('DELETE', `${org(orgId)}/user-groups/${enc(id)}`),
    setGroupMembers: (orgId: UUID, id: UUID, userIds: UUID[]): Promise<unknown> =>
      api.request('PUT', `${org(orgId)}/user-groups/${enc(id)}/members`, { body: { user_ids: userIds } }),

    // History and delivery log
    listAlerts: (orgId: UUID, q: ListQuery): Promise<unknown> => api.request('GET', `${org(orgId)}/alerts`, { query: q }),
    getAlert: (orgId: UUID, id: UUID): Promise<Alert> => api.request('GET', `${org(orgId)}/alerts/${enc(id)}`),
    listDeliveries: (orgId: UUID, q: ListQuery): Promise<unknown> => api.request('GET', `${org(orgId)}/notification-deliveries`, { query: q }),

    // Personal settings
    async getPrefs(orgId: UUID): Promise<NotificationPref[]> {
      return listOf<NotificationPref>(await api.request('GET', `${org(orgId)}/me/notification-prefs`));
    },
    putPrefs: (orgId: UUID, prefs: NotificationPref[]): Promise<unknown> => api.request('PUT', `${org(orgId)}/me/notification-prefs`, { body: prefs }),
    async channelLinks(): Promise<ChannelLink[]> {
      return listOf<ChannelLink>(await api.request('GET', '/me/channel-links'));
    },
    unlink: (kind: string): Promise<void> => api.request('DELETE', `/me/channel-links/${enc(kind)}`),
    startTelegram: (): Promise<TelegramStart> => api.request('POST', '/me/channel-links/telegram/start'),
    linkSlack: (): Promise<ChannelLink | undefined> => api.request('POST', '/me/channel-links/slack'),
    /** allow_private_urls is per org: pass the current org. */
    capabilities: (orgId?: UUID | null): Promise<AlertCapabilities> => api.request('GET', '/alerts/capabilities', { query: { org_id: orgId ?? undefined } }),
    /** Mails a code to a new personal address: 202 {verified:false, expires_at}; 429 within a minute. */
    setEmailLink: (address: string): Promise<EmailLinkPending> => api.request('PUT', '/me/channel-links/email', { body: { address } }),
    confirmEmailLink: (code: string): Promise<ChannelLink> => api.request('POST', '/me/channel-links/email/confirm', { body: { code } }),

    // In-app notifications
    listNotifications: (q: ListQuery): Promise<unknown> => api.request('GET', '/notifications', { query: q }),
    markRead: (ids: UUID[] | 'all'): Promise<unknown> => api.request('POST', '/notifications/read', { body: ids === 'all' ? { all: true } : { ids } }),
  };
}

export type AlertsApi = ReturnType<typeof alertsApi>;

/** A notification from a list or a stream event; null when it is not one. */
export function asNotification(raw: unknown): AppNotification | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.id !== 'string' || typeof o.title !== 'string') return null;
  const sev = o.severity === 'critical' || o.severity === 'warning' ? o.severity : 'info';
  return {
    id: o.id,
    alert_id: typeof o.alert_id === 'string' ? o.alert_id : null,
    title: o.title,
    body: typeof o.body === 'string' ? o.body : '',
    severity: sev,
    read_at: typeof o.read_at === 'string' ? o.read_at : null,
    created_at: typeof o.created_at === 'string' ? o.created_at : new Date().toISOString(),
  };
}
