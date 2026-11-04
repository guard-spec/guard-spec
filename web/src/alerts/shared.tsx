// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Pieces shared by the alert pages: badges, pickers and loaders.

import { Bot, Mail, MessageCircle, Send, Users, Webhook, type LucideIcon } from 'lucide-react';
import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { Badge, type Tone } from '../components/DataTable';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { normalizePage } from '../paging';
import type { Member } from '../types';
import { alertsApi } from './api';
import type { AlertCapabilities, AlertState, ChannelKind, DeliveryState, Severity } from './types';

export function useAlertsApi() {
  const { api } = useApp();
  return useMemo(() => alertsApi(api), [api]);
}

const SEV_TONE: Partial<Record<string, Tone>> = { info: 'neutral', warning: 'warn', critical: 'danger' };

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useApp();
  return <Badge tone={SEV_TONE[severity] ?? 'neutral'}>{t(`alerts.sev.${severity}` as MessageKey)}</Badge>;
}

export function AlertStateBadge({ state }: { state: AlertState }) {
  const { t } = useApp();
  return <Badge tone={state === 'firing' ? 'danger' : 'ok'}>{t(`alerts.state.${state}` as MessageKey)}</Badge>;
}

const DELIVERY_TONE: Partial<Record<string, Tone>> = { pending: 'accent', sending: 'accent', sent: 'ok', failed: 'warn', dead: 'danger' };

export function DeliveryStateBadge({ state }: { state: DeliveryState }) {
  const { t } = useApp();
  return <Badge tone={DELIVERY_TONE[state] ?? 'neutral'}>{t(`alerts.dstate.${state}` as MessageKey)}</Badge>;
}

export const KIND_ICON: Partial<Record<string, LucideIcon>> = {
  telegram: Send,
  slack: MessageCircle,
  teams: Users,
  webhook: Webhook,
  a2a: Bot,
  email: Mail,
  in_app: MessageCircle,
};

export function kindLabel(kind: string, t: (k: MessageKey) => string): string {
  return t(`alerts.kind.${kind}` as MessageKey);
}

export function KindLabel({ kind }: { kind: ChannelKind | 'in_app' }) {
  const { t } = useApp();
  const Icon = KIND_ICON[kind] ?? Webhook;
  return (
    <span className="kind-label">
      <Icon size={14} aria-hidden="true" />
      <span>{kindLabel(kind, t)}</span>
    </span>
  );
}

/** Members of the org for pickers and names; empty when the role may not list them. */
export function useMembers(): { members: Member[]; loaded: boolean } {
  const { api } = useApp();
  const { org, can } = useOrg();
  // Viewers and members may not list members: skip the call the server refuses.
  const allowed = can('members.read');
  const [members, setMembers] = useState<Member[]>([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let live = true;
    if (!allowed) {
      setLoaded(true);
      return;
    }
    api.listMembers(org.id, { limit: 200 }).then(
      (r) => {
        if (!live) return;
        setMembers(normalizePage<Member>(r).items);
        setLoaded(true);
      },
      () => live && setLoaded(true),
    );
    return () => {
      live = false;
    };
  }, [api, org.id, allowed]);
  return { members, loaded };
}

export function memberName(m: Pick<Member, 'email' | 'display_name'>): string {
  return m.display_name && m.display_name !== '' ? m.display_name : m.email;
}

/** GET /v1/alerts/capabilities; null while loading or when the server has none. */
export function useCapabilities(): AlertCapabilities | null {
  const a = useAlertsApi();
  const [caps, setCaps] = useState<AlertCapabilities | null>(null);
  useEffect(() => {
    let live = true;
    a.capabilities().then(
      (c) => live && setCaps(c),
      () => live && setCaps(null),
    );
    return () => {
      live = false;
    };
  }, [a]);
  return caps;
}

/** A searchable checkbox list of members. */
export function MemberPicker({
  label,
  members,
  selected,
  onChange,
  disabled,
  testId,
}: {
  label: string;
  members: Member[];
  selected: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  testId?: string;
}) {
  const { t } = useApp();
  const id = useId();
  const [q, setQ] = useState('');
  const needle = q.trim().toLowerCase();
  const known = new Set(members.map((m) => m.user_id));
  const unknown = selected.filter((s) => !known.has(s));
  const shown = members.filter((m) => !needle || `${m.email} ${m.display_name ?? ''}`.toLowerCase().includes(needle));
  const toggle = useCallback((uid: string, on: boolean) => onChange(on ? [...selected, uid] : selected.filter((x) => x !== uid)), [onChange, selected]);
  return (
    <div className="field picker" data-testid={testId}>
      <div className="picker-head">
        <label htmlFor={`${id}-q`}>{label}</label>
        <span className="muted small">{t('alerts.selected', { count: selected.length })}</span>
      </div>
      <input id={`${id}-q`} type="search" placeholder={t('alerts.searchMembers')} value={q} onChange={(e) => setQ(e.target.value)} />
      <ul className="picker-list" aria-label={label}>
        {shown.map((m) => (
          <li key={m.user_id}>
            <label className="check">
              <input type="checkbox" disabled={disabled} checked={selected.includes(m.user_id)} onChange={(e) => toggle(m.user_id, e.target.checked)} />
              <span className="cell-stack">
                <span>{memberName(m)}</span>
                {m.display_name ? <span className="muted small">{m.email}</span> : null}
              </span>
            </label>
          </li>
        ))}
        {unknown.map((uid) => (
          <li key={uid}>
            <label className="check">
              <input type="checkbox" disabled={disabled} checked onChange={() => toggle(uid, false)} />
              <span className="mono small">{uid}</span>
            </label>
          </li>
        ))}
        {shown.length === 0 && unknown.length === 0 ? <li className="muted small">{members.length === 0 ? t('alerts.noMembers') : t('table.noMatch')}</li> : null}
      </ul>
    </div>
  );
}

/** A group of checkboxes over options (event types, roles, channels). */
export function CheckGroup<T extends string>({
  legend,
  options,
  selected,
  onChange,
  disabled,
  error,
  columns,
}: {
  legend: string;
  options: { value: T; label: string; hint?: string }[];
  selected: T[];
  onChange: (v: T[]) => void;
  disabled?: boolean;
  error?: string;
  columns?: boolean;
}) {
  return (
    <fieldset className="check-group">
      <legend>{legend}</legend>
      <div className={columns ? 'check-grid' : 'check-row'}>
        {options.map((o) => (
          <label key={o.value} className="check" title={o.hint}>
            <input
              type="checkbox"
              disabled={disabled}
              checked={selected.includes(o.value)}
              onChange={(e) => onChange(e.target.checked ? [...selected, o.value] : selected.filter((x) => x !== o.value))}
            />
            <span>{o.label}</span>
          </label>
        ))}
      </div>
      {error ? <small className="field-error">{error}</small> : null}
    </fieldset>
  );
}
