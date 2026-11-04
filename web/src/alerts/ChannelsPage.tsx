// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Shared notification channels (contract §4): a form per kind, secrets named
// by env variable (secret_set says whether it is set, never the value), and
// "Send test" with its result under the row.

import { Eye, Pencil, Plus, Send, Trash2, X, Zap } from 'lucide-react';
import { useCallback, useState } from 'react';
import { isNotFound } from '../api';
import { authErrorText } from '../auth/errors';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, NotAvailable, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, PageHeader, Toggle } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { channelBody, channelTarget, defaultConfig, envExample, ENV_PREFIXES, validateChannel, type ChannelErrors } from './model';
import { KindLabel, kindLabel, useAlertsApi, useCapabilities } from './shared';
import { CHANNEL_KINDS, type AlertCapabilities, type ChannelInput, type ChannelKind, type ChannelTest, type NotificationChannel } from './types';

type TestState = 'running' | ChannelTest | { error: string } | 'unavailable';

export default function ChannelsPage() {
  const { t, notify } = useApp();
  const { org, can } = useOrg();
  const a = useAlertsApi();
  const caps = useCapabilities();
  const writable = can('alerts.write');
  const [editing, setEditing] = useState<{ id: string | null; value: ChannelInput; secretSet?: boolean } | null>(null);
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null);
  const [tests, setTests] = useState<Record<string, TestState>>({});
  const fetchPage = useCallback((p: { limit: number; cursor?: string }) => a.listChannels(org.id, p), [a, org.id]);
  const paged = usePaged<NotificationChannel>(fetchPage);

  const test = async (c: NotificationChannel) => {
    setTests((s) => ({ ...s, [c.id]: 'running' }));
    try {
      const r = await a.testChannel(org.id, c.id);
      setTests((s) => ({ ...s, [c.id]: r }));
    } catch (e) {
      setTests((s) => ({ ...s, [c.id]: isNotFound(e) ? 'unavailable' : { error: authErrorText(e, t) } }));
    }
  };

  const columns: Column<NotificationChannel>[] = [
    {
      key: 'name',
      header: t('common.name'),
      className: 'col-name',
      cell: (c) => (
        <strong className="ellipsis" title={c.name}>
          {c.name}
        </strong>
      ),
    },
    { key: 'kind', header: t('alerts.channel.kind'), className: 'nowrap', cell: (c) => <KindLabel kind={c.kind} /> },
    {
      key: 'target',
      header: t('alerts.channel.target'),
      className: 'col-url',
      cell: (c) => {
        const target = channelTarget(c.kind, c.config ?? {});
        return (
          <span className="mono small ellipsis" title={target || undefined}>
            {target || '—'}
          </span>
        );
      },
    },
    {
      key: 'secret',
      header: t('alerts.channel.secret'),
      className: 'col-env',
      cell: (c) =>
        c.kind === 'email' ? (
          <span className="muted small">{t('alerts.channel.smtpGlobal')}</span>
        ) : c.secret_env ? (
          <div className="cell-stack">
            <span className="mono small ellipsis" title={`$${c.secret_env}`}>
              ${c.secret_env}
            </span>
            <SecretBadge set={c.secret_set} />
          </div>
        ) : (
          <span className="muted small">{t('alerts.channel.noSecret')}</span>
        ),
    },
    {
      key: 'status',
      header: t('prov.status'),
      className: 'nowrap',
      cell: (c) => (
        <span className="badges">
          <Badge tone={c.enabled ? 'ok' : 'off'}>{c.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
          <TestBadge r={tests[c.id]} />
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (c) => (
        <span className="icon-actions">
          {writable ? (
            <button
              type="button"
              className="btn btn-small btn-square"
              aria-label={t('alerts.channel.testOf', { name: c.name })}
              title={t('alerts.sendTest')}
              disabled={tests[c.id] === 'running'}
              onClick={() => void test(c)}
            >
              <Zap size={14} aria-hidden="true" />
            </button>
          ) : null}
          <button
            type="button"
            className="btn btn-small btn-square"
            aria-label={writable ? t('alerts.channel.editOf', { name: c.name }) : t('alerts.viewOf', { name: c.name })}
            title={writable ? t('common.edit') : t('alerts.view')}
            onClick={() =>
              setEditing({ id: c.id, value: { name: c.name, kind: c.kind, config: { ...defaultConfig(c.kind), ...(c.config ?? {}) }, secret_env: c.secret_env, enabled: c.enabled }, secretSet: c.secret_set })
            }
          >
            {writable ? <Pencil size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
          </button>
          {writable ? (
            <button type="button" className="btn btn-small btn-square btn-danger" aria-label={`${t('common.delete')} ${c.name}`} title={t('common.delete')} onClick={() => setDeleting(c)}>
              <Trash2 size={14} aria-hidden="true" />
            </button>
          ) : null}
        </span>
      ),
    },
  ];

  const openNew = () => setEditing({ id: null, value: { name: '', kind: 'slack', config: defaultConfig('slack'), secret_env: '', enabled: true } });
  return (
    <div>
      <PageHeader
        title={t('nav.alertChannels')}
        help={t('alerts.channels.help')}
        actions={
          writable ? (
            <button type="button" className="btn btn-primary btn-icon-text" onClick={openNew}>
              <Plus size={16} aria-hidden="true" />
              <span>{t('alerts.channel.new')}</span>
            </button>
          ) : null
        }
      />
      {!writable ? <p className="banner banner-info small">{t('alerts.readOnly')}</p> : null}
      <DataTable
        columns={columns}
        paged={paged}
        rowKey={(c) => c.id}
        rowClassName={(c) => (c.enabled ? '' : 'row-muted')}
        testId="channels-table"
        feature={t('nav.alertChannels')}
        rowDetail={(c) => {
          const r = tests[c.id];
          return r && r !== 'running' ? <TestResult r={r} name={c.name} onDismiss={() => setTests((s) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== c.id)))} /> : null;
        }}
        empty={
          <EmptyState
            icon={Send}
            title={t('alerts.channels.empty')}
            body={t('alerts.channels.emptyBody')}
            action={
              writable ? (
                <button type="button" className="btn btn-primary" onClick={openNew}>
                  {t('alerts.channel.new')}
                </button>
              ) : null
            }
          />
        }
      />
      {editing ? (
        <ChannelEditor
          key={editing.id ?? 'new'}
          id={editing.id}
          initial={editing.value}
          secretSet={editing.secretSet}
          readOnly={!writable}
          caps={caps}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await paged.reload();
          }}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        title={t('alerts.channel.delete')}
        body={t('alerts.channel.confirmDelete', { name: deleting?.name ?? '' })}
        confirmLabel={t('common.delete')}
        danger
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await a.deleteChannel(org.id, deleting.id);
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

function SecretBadge({ set }: { set: boolean | undefined }) {
  const { t } = useApp();
  if (set === undefined) return null;
  return (
    <Badge tone={set ? 'ok' : 'warn'} title={set ? t('alerts.channel.secretSetHelp') : t('alerts.channel.secretMissingHelp')}>
      {set ? t('alerts.channel.secretSet') : t('alerts.channel.secretMissing')}
    </Badge>
  );
}

function TestBadge({ r }: { r: TestState | undefined }) {
  const { t } = useApp();
  if (!r) return null;
  if (r === 'running') return <Badge tone="accent">{t('alerts.testing')}</Badge>;
  if (r === 'unavailable') return null;
  if ('ok' in r) return <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? t('alerts.testOk') : t('alerts.testFailed')}</Badge>;
  return <Badge tone="danger">{t('alerts.testFailed')}</Badge>;
}

/** The outcome of "Send test": ok, HTTP status, latency and the error. */
export function TestResult({ r, name, onDismiss }: { r: Exclude<TestState, 'running'>; name: string; onDismiss: () => void }) {
  const { t } = useApp();
  let body;
  if (r === 'unavailable') body = <NotAvailable compact />;
  else if ('ok' in r) {
    body = (
      <>
        <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? t('alerts.testOk') : t('alerts.testFailed')}</Badge>
        {r.status !== null && r.status !== undefined ? <span className="muted"> · HTTP {r.status}</span> : null}
        {r.latency_ms !== null && r.latency_ms !== undefined ? <span className="muted"> · {r.latency_ms} ms</span> : null}
        {r.error ? <div className="field-error">{r.error}</div> : null}
      </>
    );
  } else body = <span className="field-error">{r.error}</span>;
  return (
    <div className="test-result small" data-testid="channel-test-result" role="status">
      <strong className="test-title">{t('alerts.channel.testResultOf', { name })}</strong>
      <div className="test-body">{body}</div>
      <button type="button" className="btn-icon" aria-label={t('common.dismiss')} onClick={onDismiss}>
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  );
}

/** Kinds offered for a new channel (an existing one keeps its kind). */
function kindAvailable(kind: ChannelKind, caps: AlertCapabilities | null): boolean {
  if (!caps) return true;
  switch (kind) {
    case 'email':
      return caps.smtp !== false;
    case 'a2a':
      return caps.a2a !== false;
    case 'webhook':
      return caps.webhook !== false;
    case 'teams':
      return caps.teams !== false;
    default:
      return true;
  }
}

function ChannelEditor({
  id,
  initial,
  secretSet,
  readOnly,
  caps,
  onClose,
  onSaved,
}: {
  id: string | null;
  initial: ChannelInput;
  secretSet: boolean | undefined;
  readOnly: boolean;
  caps: AlertCapabilities | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [v, setV] = useState<ChannelInput>(initial);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const allowPrivate = caps?.allow_private_urls === true;
  const errors: ChannelErrors = touched ? validateChannel(v, allowPrivate) : {};
  const err = (k: keyof ChannelErrors) => (errors[k] ? t(`alerts.err.${errors[k]}` as MessageKey, { prefixes: ENV_PREFIXES.join(', ') }) : undefined);
  const cfg = v.config;
  const cs = (k: string) => (typeof cfg[k] === 'string' ? cfg[k] : '');
  const setCfg = (patch: Record<string, unknown>) => setV((x) => ({ ...x, config: { ...x.config, ...patch } }));
  const slackMode = cfg.mode === 'bot' ? 'bot' : 'webhook';

  const save = async () => {
    setTouched(true);
    setError(null);
    if (Object.keys(validateChannel(v, allowPrivate)).length > 0) return;
    setSaving(true);
    try {
      const body = channelBody(v);
      if (id) {
        // The kind of a channel does not change.
        await a.updateChannel(org.id, id, { name: body.name, config: body.config, secret_env: body.secret_env, enabled: body.enabled });
      } else await a.createChannel(org.id, body);
      notify(t('common.saved'));
      await onSaved();
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setSaving(false);
    }
  };

  const secretHelp = (): string => {
    switch (v.kind) {
      case 'telegram':
        return t('alerts.channel.envTelegram', { example: envExample('telegram') });
      case 'slack':
        return slackMode === 'bot' ? t('alerts.channel.envSlackBot', { example: envExample('slack', 'bot') }) : t('alerts.channel.envSlackWebhook', { example: envExample('slack', 'webhook') });
      case 'teams':
        return t('alerts.channel.envTeams', { example: envExample('teams') });
      case 'webhook':
        return t('alerts.channel.envWebhook', { example: envExample('webhook') });
      case 'a2a':
        return t('alerts.channel.envA2a', { example: envExample('a2a') });
      case 'email':
        return '';
    }
  };

  return (
    <Dialog
      open
      wide
      title={readOnly ? t('alerts.channel.view') : id ? t('alerts.channel.edit') : t('alerts.channel.new')}
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
        data-testid="channel-editor"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <ErrorBanner error={error} />
        <fieldset disabled={readOnly}>
          <legend className="sr-only">{t('alerts.channel.kind')}</legend>
          <div className="form-grid">
            <Field label={t('common.name')} error={err('name')}>
              {(p) => <input {...p} value={v.name} onChange={(e) => setV((x) => ({ ...x, name: e.target.value }))} />}
            </Field>
            <Field label={t('alerts.channel.kind')} help={id ? t('alerts.channel.kindFixed') : undefined}>
              {(p) => (
                <select
                  {...p}
                  value={v.kind}
                  disabled={id !== null || readOnly}
                  onChange={(e) => {
                    const kind = e.target.value as ChannelKind;
                    setV((x) => ({ ...x, kind, config: defaultConfig(kind), secret_env: kind === 'email' ? null : (x.secret_env ?? '') }));
                    setTouched(false);
                  }}
                >
                  {CHANNEL_KINDS.filter((k) => k === v.kind || kindAvailable(k, caps)).map((k) => (
                    <option key={k} value={k}>
                      {kindLabel(k, t)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
          </div>
          <p className="muted small">{t(`alerts.kindHelp.${v.kind}` as MessageKey)}</p>
        </fieldset>
        <fieldset disabled={readOnly}>
          <legend>{t('alerts.channel.settings')}</legend>
          {v.kind === 'telegram' ? (
            <Field label={t('alerts.channel.chatId')} help={t('alerts.channel.chatIdHelp')} error={err('chat_id')}>
              {(p) => <input {...p} className="mono" value={cs('chat_id')} placeholder="-1001234567890" onChange={(e) => setCfg({ chat_id: e.target.value })} />}
            </Field>
          ) : null}
          {v.kind === 'slack' ? (
            <>
              <div className="radio-list" role="radiogroup" aria-label={t('alerts.channel.slackMode')}>
                {(['webhook', 'bot'] as const).map((m) => (
                  <label key={m} className="check">
                    <input type="radio" name="slack-mode" checked={slackMode === m} onChange={() => setCfg({ mode: m })} />
                    <span>{t(m === 'bot' ? 'alerts.channel.slackBot' : 'alerts.channel.slackWebhook')}</span>
                  </label>
                ))}
              </div>
              <Field label={t('alerts.channel.slackChannel')} help={slackMode === 'bot' ? t('alerts.channel.slackChannelHelp') : t('alerts.channel.optional')} error={err('channel')}>
                {(p) => <input {...p} className="mono" value={cs('channel')} placeholder="#security-alerts" onChange={(e) => setCfg({ channel: e.target.value })} />}
              </Field>
            </>
          ) : null}
          {v.kind === 'webhook' ? (
            <>
              <Field label={t('alerts.channel.url')} help={t('alerts.channel.urlHelp')} error={err('url')}>
                {(p) => <input {...p} className="mono" type="url" value={cs('url')} placeholder="https://siem.example.com/hooks/guardspec" onChange={(e) => setCfg({ url: e.target.value })} />}
              </Field>
              {allowPrivate ? (
                <Toggle label={t('alerts.channel.allowPrivate')} help={t('alerts.channel.allowPrivateHelp')} checked={cfg.allow_private === true} disabled={readOnly} onChange={(on) => setCfg({ allow_private: on })} />
              ) : null}
            </>
          ) : null}
          {v.kind === 'a2a' ? (
            <Field label={t('alerts.channel.agentCard')} help={t('alerts.channel.agentCardHelp')} error={err('agent_card_url')}>
              {(p) => <input {...p} className="mono" type="url" value={cs('agent_card_url')} placeholder="https://agent.example.com" onChange={(e) => setCfg({ agent_card_url: e.target.value })} />}
            </Field>
          ) : null}
          {v.kind === 'email' ? (
            <>
              <ChipsInput
                label={t('alerts.channel.to')}
                values={Array.isArray(cfg.to) ? (cfg.to as string[]) : []}
                onChange={(to) => setCfg({ to })}
                placeholder="secops@example.com"
                help={t('alerts.channel.toHelp')}
              />
              {err('to') ? <small className="field-error">{err('to')}</small> : null}
            </>
          ) : null}
          {v.kind === 'teams' ? <p className="muted small">{t('alerts.channel.teamsHelp')}</p> : null}
          {v.kind !== 'email' ? (
            <Field label={t('alerts.channel.secretEnv')} help={secretHelp()} error={err('secret_env')}>
              {(p) => (
                <div className="input-with-badge">
                  <input
                    {...p}
                    className="mono"
                    value={v.secret_env ?? ''}
                    placeholder={envExample(v.kind, slackMode)}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(e) => setV((x) => ({ ...x, secret_env: e.target.value.toUpperCase() }))}
                  />
                  {id && v.secret_env === initial.secret_env ? <SecretBadge set={secretSet} /> : null}
                </div>
              )}
            </Field>
          ) : null}
          <Toggle label={t('alerts.channel.enabled')} checked={v.enabled} disabled={readOnly} onChange={(enabled) => setV((x) => ({ ...x, enabled }))} />
        </fieldset>
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
