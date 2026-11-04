// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Alert rules (contract §2, §7): the list with an enable switch and "Send
// test", and the editor of every rule field.

import { Bell, Eye, Pencil, Plus, Trash2, Zap } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { authErrorText } from '../auth/errors';
import { Badge, DataTable, EmptyState, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, RelativeTime, Toggle } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { ROLES, type Role } from '../types';
import { ConditionEditor } from './ConditionEditor';
import { defaultQuietHours, formatSeconds, newRule, ruleBody, ruleInput, validateRule, type RuleErrors } from './model';
import { CheckGroup, MemberPicker, SeverityBadge, useAlertsApi, useMembers, kindLabel } from './shared';
import { EVENT_TYPE_GROUPS, GROUP_BY_KEYS, SEVERITIES, type AlertRule, type AlertRuleInput, type NotificationChannel, type Severity, type UserGroup } from './types';

function timeZones(): string[] {
  try {
    return (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? [];
  } catch {
    return [];
  }
}

function localZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

export default function RulesPage() {
  const { t, notify } = useApp();
  const { org, can } = useOrg();
  const a = useAlertsApi();
  const writable = can('alerts.write');
  const [editing, setEditing] = useState<{ id: string | null; value: AlertRuleInput } | null>(null);
  const [deleting, setDeleting] = useState<AlertRule | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // The switch moves at once; the list catches up after the PATCH.
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const { members } = useMembers();

  useEffect(() => {
    let live = true;
    a.allGroups(org.id).then((g) => live && setGroups(g), () => undefined);
    a.allChannels(org.id).then((c) => live && setChannels(c), () => undefined);
    return () => {
      live = false;
    };
  }, [a, org.id]);

  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => a.listRules(org.id, p), [a, org.id]);
  const paged = usePaged<AlertRule>(fetchPage);

  const sendTest = async (r: AlertRule) => {
    setBusy(r.id);
    try {
      const res = await a.testRule(org.id, r.id);
      notify(t('alerts.rule.testSent', { name: r.name, id: res?.alert_id?.slice(0, 8) ?? '—' }));
    } catch (e) {
      notify(authErrorText(e, t), 'error');
    } finally {
      setBusy(null);
    }
  };

  const setEnabled = async (r: AlertRule, enabled: boolean) => {
    setBusy(r.id);
    setToggled((x) => ({ ...x, [r.id]: enabled }));
    try {
      await a.updateRule(org.id, r.id, { enabled });
      notify(enabled ? t('alerts.rule.enabledMsg', { name: r.name }) : t('alerts.rule.disabledMsg', { name: r.name }));
      await paged.reload();
    } catch (e) {
      notify(authErrorText(e, t), 'error');
    } finally {
      setBusy(null);
      setToggled((x) => Object.fromEntries(Object.entries(x).filter(([k]) => k !== r.id)));
    }
  };

  const summary = (r: AlertRule) => {
    const rc = r.recipients ?? { user_ids: [], group_ids: [], roles: [] };
    const parts: string[] = [];
    if (rc.user_ids?.length) parts.push(t('alerts.rule.nUsers', { count: rc.user_ids.length }));
    if (rc.group_ids?.length) parts.push(t('alerts.rule.nGroups', { count: rc.group_ids.length }));
    if (rc.roles?.length) parts.push(rc.roles.map((x) => t(`org.role.${x}` as MessageKey)).join(', '));
    if (r.channel_ids?.length) parts.push(t('alerts.rule.nChannels', { count: r.channel_ids.length }));
    return parts.join(' · ') || '—';
  };

  const columns: Column<AlertRule>[] = [
    {
      key: 'name',
      header: t('common.name'),
      className: 'col-rule',
      cell: (r) => (
        <div className="cell-stack">
          <strong className="ellipsis" title={r.name}>
            {r.name}
          </strong>
          <span className="muted small mono ellipsis" title={r.event_types.join(', ')}>
            {r.event_types.slice(0, 2).join(', ')}
            {r.event_types.length > 2 ? ` +${r.event_types.length - 2}` : ''}
          </span>
        </div>
      ),
    },
    { key: 'severity', header: t('alerts.severity'), cell: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: 'trigger',
      header: t('alerts.rule.trigger'),
      className: 'nowrap small',
      cell: (r) => (
        <div className="cell-stack">
          <span>{t('alerts.rule.triggerText', { n: r.threshold, window: formatSeconds(r.window_seconds) })}</span>
          {r.condition ? (
            <span className="muted mono ellipsis cond-snippet" title={r.condition}>
              {r.condition}
            </span>
          ) : null}
        </div>
      ),
    },
    { key: 'recipients', header: t('alerts.rule.recipients'), className: 'small col-wide-only', cell: (r) => <span className="ellipsis recip-snippet">{summary(r)}</span> },
    {
      key: 'enabled',
      header: t('alerts.enabled'),
      className: 'nowrap',
      cell: (r) => (
        <label className="switch" title={r.enabled ? t('common.enabled') : t('common.disabled')}>
          <input
            type="checkbox"
            role="switch"
            checked={toggled[r.id] ?? r.enabled}
            disabled={!writable || busy === r.id}
            aria-label={t('alerts.rule.enableOf', { name: r.name })}
            onChange={(e) => void setEnabled(r, e.target.checked)}
          />
          <span className="switch-track" aria-hidden="true" />
        </label>
      ),
    },
    { key: 'updated', header: t('alerts.updated'), className: 'nowrap small col-wide-only', cell: (r) => <RelativeTime value={r.updated_at ?? r.created_at} /> },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (r) => (
        <span className="icon-actions">
          {writable ? (
            <button
              type="button"
              className="btn btn-small btn-square"
              aria-label={t('alerts.rule.testOf', { name: r.name })}
              title={t('alerts.sendTest')}
              disabled={busy === r.id}
              onClick={() => void sendTest(r)}
            >
              <Zap size={14} aria-hidden="true" />
            </button>
          ) : null}
          <button
            type="button"
            className="btn btn-small btn-square"
            aria-label={writable ? t('alerts.rule.editOf', { name: r.name }) : t('alerts.viewOf', { name: r.name })}
            title={writable ? t('common.edit') : t('alerts.view')}
            onClick={() => setEditing({ id: r.id, value: ruleInput(r) })}
          >
            {writable ? <Pencil size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
          </button>
          {writable ? (
            <button type="button" className="btn btn-small btn-square btn-danger" aria-label={`${t('common.delete')} ${r.name}`} title={t('common.delete')} onClick={() => setDeleting(r)}>
              <Trash2 size={14} aria-hidden="true" />
            </button>
          ) : null}
        </span>
      ),
    },
  ];

  const openNew = () => setEditing({ id: null, value: newRule() });
  return (
    <div>
      <PageHeader
        title={t('nav.alertRules')}
        help={t('alerts.rules.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={openNew}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('alerts.rule.new')}</span>
            </button>
          ) : null
        }
      />
      {!writable ? <p className="banner banner-info small">{t('alerts.readOnly')}</p> : null}
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(r) => r.id}
        rowClassName={(r) => (r.enabled ? '' : 'row-muted')}
        testId="alert-rules-table"
        feature={t('nav.alertRules')}
        empty={
          <EmptyState
            icon={Bell}
            title={t('alerts.rules.empty')}
            body={t('alerts.rules.emptyBody')}
            action={
              writable ? (
                <button type="button" className="btn btn-primary" onClick={openNew}>
                  {t('alerts.rule.new')}
                </button>
              ) : null
            }
          />
        }
      />
      {editing ? (
        <RuleEditor
          key={editing.id ?? 'new'}
          id={editing.id}
          initial={editing.value}
          readOnly={!writable}
          groups={groups}
          channels={channels}
          members={members}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await paged.reload();
          }}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        title={t('alerts.rule.delete')}
        body={t('common.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await a.deleteRule(org.id, deleting.id);
            notify(t('common.deleted'));
            await paged.reload();
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setDeleting(null);
        }}
      />
    </div>
  );
}

function RuleEditor({
  id,
  initial,
  readOnly,
  groups,
  channels,
  members,
  onClose,
  onSaved,
}: {
  id: string | null;
  initial: AlertRuleInput;
  readOnly: boolean;
  groups: UserGroup[];
  channels: NotificationChannel[];
  members: ReturnType<typeof useMembers>['members'];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [v, setV] = useState<AlertRuleInput>(initial);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const zones = useMemo(() => timeZones(), []);
  const errors: RuleErrors = touched ? validateRule(v) : {};
  const set = (patch: Partial<AlertRuleInput>) => setV((x) => ({ ...x, ...patch }));
  const err = (k: keyof RuleErrors) => {
    const e = errors[k];
    if (!e) return undefined;
    if (k === 'condition') return t('alerts.err.condition', { error: e });
    return t(`alerts.err.${e}` as MessageKey);
  };

  const save = async () => {
    setTouched(true);
    setError(null);
    if (Object.keys(validateRule(v)).length > 0) return;
    setSaving(true);
    try {
      const body = ruleBody(v);
      if (id) await a.updateRule(org.id, id, body);
      else await a.createRule(org.id, body);
      notify(t('common.saved'));
      await onSaved();
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setSaving(false);
    }
  };

  const num = (s: string) => (s.trim() === '' ? NaN : Number(s));
  const title = readOnly ? t('alerts.rule.view') : id ? t('alerts.rule.edit') : t('alerts.rule.new');
  const roleOptions = ROLES.map((r) => ({ value: r, label: t(`org.role.${r}` as MessageKey) }));
  return (
    <Dialog
      open
      wide
      title={title}
      onClose={onClose}
      footer={
        readOnly ? (
          <button type="button" className="btn" onClick={onClose}>
            {t('common.close')}
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={saving} onClick={() => void save()}>
              {saving ? t('common.saving') : t('common.save')}
            </button>
          </>
        )
      }
    >
      <form
        className="rule-editor"
        data-testid="rule-editor"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <ErrorBanner error={error} />
        {touched && Object.keys(errors).length > 0 ? (
          <p className="banner banner-error small" role="alert">
            {t('alerts.err.fix')}
          </p>
        ) : null}
        <fieldset disabled={readOnly}>
          <legend className="sr-only">{t('alerts.rule.basics')}</legend>
          <div className="form-grid">
            <Field label={t('common.name')} error={err('name')}>
              {(p) => <input {...p} value={v.name} maxLength={120} onChange={(e) => set({ name: e.target.value })} />}
            </Field>
            <Field label={t('alerts.severity')} help={t('alerts.rule.severityHelp')}>
              {(p) => (
                <select {...p} value={v.severity} onChange={(e) => set({ severity: e.target.value as Severity })}>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {t(`alerts.sev.${s}` as MessageKey)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
          </div>
          <Toggle label={t('alerts.rule.enabled')} checked={v.enabled} disabled={readOnly} onChange={(enabled) => set({ enabled })} />
        </fieldset>

        <fieldset disabled={readOnly}>
          <legend>{t('alerts.rule.events')}</legend>
          <div className="event-groups">
            {EVENT_TYPE_GROUPS.map((g) => (
              <CheckGroup
                key={g.id}
                legend={t(`alerts.evgroup.${g.id}` as MessageKey)}
                options={g.types.map((x) => ({ value: x, label: x, hint: t(`alerts.ev.${x}` as MessageKey) }))}
                selected={v.event_types}
                onChange={(event_types) => set({ event_types })}
                disabled={readOnly}
              />
            ))}
          </div>
          {err('event_types') ? <small className="field-error">{err('event_types')}</small> : null}
        </fieldset>

        <ConditionEditor value={v.condition} onChange={(condition) => set({ condition })} readOnly={readOnly} serverError={touched ? err('condition') : null} />

        <fieldset disabled={readOnly}>
          <legend>{t('alerts.rule.trigger')}</legend>
          <div className="form-grid">
            <Field label={t('alerts.rule.threshold')} help={t('alerts.rule.thresholdHelp')} error={err('threshold')}>
              {(p) => <input {...p} type="number" min={1} step={1} value={Number.isNaN(v.threshold) ? '' : v.threshold} onChange={(e) => set({ threshold: num(e.target.value) })} />}
            </Field>
            <Field
              label={t('alerts.rule.window')}
              help={Number.isFinite(v.window_seconds) ? t('alerts.rule.secondsIs', { text: formatSeconds(v.window_seconds) }) : t('alerts.rule.windowHelp')}
              error={err('window_seconds')}
            >
              {(p) => <input {...p} type="number" min={60} max={86400} step={60} value={Number.isNaN(v.window_seconds) ? '' : v.window_seconds} onChange={(e) => set({ window_seconds: num(e.target.value) })} />}
            </Field>
            <Field
              label={t('alerts.rule.throttle')}
              help={Number.isFinite(v.throttle_seconds) ? t('alerts.rule.throttleHelp', { text: formatSeconds(v.throttle_seconds) }) : undefined}
              error={err('throttle_seconds')}
            >
              {(p) => <input {...p} type="number" min={0} step={60} value={Number.isNaN(v.throttle_seconds) ? '' : v.throttle_seconds} onChange={(e) => set({ throttle_seconds: num(e.target.value) })} />}
            </Field>
          </div>
          <CheckGroup
            legend={t('alerts.rule.groupBy')}
            options={GROUP_BY_KEYS.map((k) => ({ value: k, label: k }))}
            selected={v.group_by}
            onChange={(group_by) => set({ group_by })}
            disabled={readOnly}
          />
          <p className="muted small">{t('alerts.rule.groupByHelp')}</p>
          <Toggle label={t('alerts.rule.autoResolve')} help={t('alerts.rule.autoResolveHelp')} checked={v.auto_resolve} disabled={readOnly} onChange={(auto_resolve) => set({ auto_resolve })} />
        </fieldset>

        <fieldset disabled={readOnly}>
          <legend>{t('alerts.rule.quietHours')}</legend>
          <Toggle
            label={t('alerts.rule.quietOn')}
            help={t('alerts.rule.quietHelp')}
            checked={v.quiet_hours !== null}
            disabled={readOnly}
            onChange={(on) => set({ quiet_hours: on ? defaultQuietHours(localZone()) : null })}
          />
          {v.quiet_hours ? (
            <>
              <div className="form-grid">
                <Field label={t('alerts.rule.tz')}>
                  {(p) => (
                    <>
                      <input
                        {...p}
                        list={zones.length ? 'alert-tz-list' : undefined}
                        value={v.quiet_hours?.tz ?? ''}
                        onChange={(e) => v.quiet_hours && set({ quiet_hours: { ...v.quiet_hours, tz: e.target.value } })}
                      />
                      {zones.length ? (
                        <datalist id="alert-tz-list">
                          {zones.map((z) => (
                            <option key={z} value={z} />
                          ))}
                        </datalist>
                      ) : null}
                    </>
                  )}
                </Field>
                <Field label={t('alerts.rule.start')}>
                  {(p) => <input {...p} type="time" value={v.quiet_hours?.start ?? ''} onChange={(e) => v.quiet_hours && set({ quiet_hours: { ...v.quiet_hours, start: e.target.value } })} />}
                </Field>
                <Field label={t('alerts.rule.end')}>
                  {(p) => <input {...p} type="time" value={v.quiet_hours?.end ?? ''} onChange={(e) => v.quiet_hours && set({ quiet_hours: { ...v.quiet_hours, end: e.target.value } })} />}
                </Field>
                <Field label={t('alerts.rule.quietMode')}>
                  {(p) => (
                    <select {...p} value={v.quiet_hours?.mode} onChange={(e) => v.quiet_hours && set({ quiet_hours: { ...v.quiet_hours, mode: e.target.value as 'suppress' | 'delay' } })}>
                      <option value="suppress">{t('alerts.rule.modeSuppress')}</option>
                      <option value="delay">{t('alerts.rule.modeDelay')}</option>
                    </select>
                  )}
                </Field>
              </div>
              <Toggle
                label={t('alerts.rule.criticalBypass')}
                checked={v.quiet_hours.critical_bypass}
                disabled={readOnly}
                onChange={(critical_bypass) => v.quiet_hours && set({ quiet_hours: { ...v.quiet_hours, critical_bypass } })}
              />
              {err('quiet_hours') ? <small className="field-error">{err('quiet_hours')}</small> : null}
            </>
          ) : null}
        </fieldset>

        <fieldset disabled={readOnly}>
          <legend>{t('alerts.rule.recipients')}</legend>
          <p className="muted small">{t('alerts.rule.recipientsHelp')}</p>
          <MemberPicker
            label={t('alerts.rule.users')}
            members={members}
            selected={v.recipients.user_ids}
            disabled={readOnly}
            onChange={(user_ids) => set({ recipients: { ...v.recipients, user_ids } })}
            testId="rule-users"
          />
          <div className="form-grid">
            <CheckGroup
              legend={t('alerts.rule.groups')}
              options={groups.map((g) => ({ value: g.id, label: g.name }))}
              selected={v.recipients.group_ids}
              disabled={readOnly}
              onChange={(group_ids) => set({ recipients: { ...v.recipients, group_ids } })}
            />
            <CheckGroup<Role>
              legend={t('alerts.rule.roles')}
              options={roleOptions}
              selected={v.recipients.roles}
              disabled={readOnly}
              onChange={(roles) => set({ recipients: { ...v.recipients, roles } })}
            />
          </div>
          {groups.length === 0 ? <p className="muted small">{t('alerts.rule.noGroups')}</p> : null}
          <CheckGroup
            legend={t('alerts.rule.channels')}
            options={channels.map((c) => ({ value: c.id, label: `${c.name} (${kindLabel(c.kind, t)})` }))}
            selected={v.channel_ids}
            disabled={readOnly}
            onChange={(channel_ids) => set({ channel_ids })}
            columns
          />
          {channels.length === 0 ? <p className="muted small">{t('alerts.rule.noChannels')}</p> : null}
          {err('recipients') ? <small className="field-error">{err('recipients')}</small> : null}
          <p className="muted small">
            <Badge tone="accent">{t('alerts.inApp')}</Badge> {t('alerts.rule.inAppHelp')}
          </p>
        </fieldset>
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
