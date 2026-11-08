// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Shared notification channels (docs/alerts.md §4): a form per kind, secrets
// named by env variable (secret_set says whether it is set, never the value),
// "Send test" with its result under the row, and verification: Telegram on
// the instance bot links a group with a /link command, email addresses
// confirm by mail (double opt-in).

import { Eye, MailCheck, Pencil, Plus, Send, ShieldCheck, Trash2, X, Zap } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, isNotFound } from '../api';
import { authErrorText } from '../auth/errors';
import { ChipsInput } from '../components/ChipsInput';
import { Badge, DataTable, EmptyState, NotAvailable, type Column } from '../components/DataTable';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, CopyButton, Dialog, ErrorBanner, Field, PageHeader, RelativeTime, Toggle } from '../components/ui';
import { useApp, useOrg } from '../context';
import type { MessageKey } from '../i18n';
import { channelBody, channelTarget, defaultConfig, envExample, kindPrefixes, onInstanceBot, validateChannel, type ChannelErrors } from './model';
import { KindLabel, kindLabel, useAlertsApi, useCapabilities } from './shared';
import {
  CHANNEL_KINDS,
  type AlertCapabilities,
  type ChannelInput,
  type ChannelKind,
  type ChannelTest,
  type EmailAddressState,
  type NotificationChannel,
  type TelegramChannelLink,
} from './types';

/** Email addresses of a channel that still wait for their confirmation. */
export function unconfirmed(c: Pick<NotificationChannel, 'kind' | 'addresses'>): EmailAddressState[] {
  return c.kind === 'email' ? (c.addresses ?? []).filter((x) => !x.confirmed) : [];
}

/** "Verify" applies to Telegram channels on the instance bot. */
export function needsTelegramLink(c: Pick<NotificationChannel, 'kind' | 'secret_env'>): boolean {
  return onInstanceBot(c);
}

type TestState = 'running' | ChannelTest | { error: string } | 'unavailable';

export default function ChannelsPage() {
  const { t, notify } = useApp();
  const { org, can } = useOrg();
  const a = useAlertsApi();
  const caps = useCapabilities(org.id);
  const writable = can('alerts.write');
  const [editing, setEditing] = useState<{ id: string | null; value: ChannelInput; secretSet?: boolean; addresses?: EmailAddressState[] | null } | null>(null);
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null);
  const [verifying, setVerifying] = useState<NotificationChannel | null>(null);
  const [resending, setResending] = useState<string | null>(null);
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

  const resend = async (c: NotificationChannel) => {
    setResending(c.id);
    try {
      await a.resendEmailConfirmations(org.id, c.id);
      notify(t('alerts.channel.confirmationsSent', { count: unconfirmed(c).length, name: c.name }));
      await paged.reload();
    } catch (e) {
      notify(e instanceof ApiError && e.status === 429 ? t('alerts.channel.capReached') : authErrorText(e, t), 'error');
    } finally {
      setResending(null);
    }
  };

  const columns: Column<NotificationChannel>[] = [
    {
      key: 'name',
      header: t('common.name'),
      className: 'col-name',
      // The kind under the name: one column less, so the table fits at 1280px.
      cell: (c) => (
        <div className="cell-stack">
          <strong className="ellipsis" title={c.name}>
            {c.name}
          </strong>
          <span className="muted small nowrap">
            <KindLabel kind={c.kind} />
          </span>
        </div>
      ),
    },
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
      // Badges wrap (enabled, verification, test): no nowrap.
      className: 'col-status',
      cell: (c) => (
        <span className="badges">
          <Badge tone={c.enabled ? 'ok' : 'off'}>{c.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
          <VerifiedBadge c={c} />
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
          {writable && needsTelegramLink(c) ? (
            <button
              type="button"
              className={c.verified === false ? 'btn btn-small btn-square btn-attention' : 'btn btn-small btn-square'}
              aria-label={t('alerts.channel.verifyOf', { name: c.name })}
              title={t('alerts.channel.verify')}
              onClick={() => setVerifying(c)}
            >
              <ShieldCheck size={14} aria-hidden="true" />
            </button>
          ) : null}
          {writable && unconfirmed(c).length > 0 ? (
            <button
              type="button"
              className="btn btn-small btn-square"
              aria-label={t('alerts.channel.resendOf', { name: c.name })}
              title={t('alerts.channel.resend')}
              disabled={resending === c.id}
              onClick={() => void resend(c)}
            >
              <MailCheck size={14} aria-hidden="true" />
            </button>
          ) : null}
          <button
            type="button"
            className="btn btn-small btn-square"
            aria-label={writable ? t('alerts.channel.editOf', { name: c.name }) : t('alerts.viewOf', { name: c.name })}
            title={writable ? t('common.edit') : t('alerts.view')}
            onClick={() =>
              setEditing({
                id: c.id,
                value: { name: c.name, kind: c.kind, config: { ...defaultConfig(c.kind), ...(c.config ?? {}) }, secret_env: c.secret_env, enabled: c.enabled },
                secretSet: c.secret_set,
                addresses: c.addresses,
              })
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
          addresses={editing.addresses ?? null}
          readOnly={!writable}
          caps={caps}
          onClose={() => setEditing(null)}
          onSaved={async (saved) => {
            const wasNew = editing.id === null;
            setEditing(null);
            await paged.reload();
            // A new group channel on the instance bot goes straight to its /link step.
            if (wasNew && saved && needsTelegramLink(saved) && saved.verified !== true) setVerifying(saved);
          }}
        />
      ) : null}
      {verifying ? (
        <TelegramVerifyDialog
          key={verifying.id}
          channel={verifying}
          onClose={() => setVerifying(null)}
          onVerified={async () => {
            setVerifying(null);
            notify(t('alerts.channel.verifiedMsg', { name: verifying.name }));
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

/** Verification (docs/alerts.md §4): shown for the kinds that need it. */
function VerifiedBadge({ c }: { c: NotificationChannel }) {
  const { t } = useApp();
  if (c.kind === 'email' && c.addresses && c.addresses.length > 0) {
    const ok = c.addresses.filter((x) => x.confirmed).length;
    return (
      <Badge tone={ok === c.addresses.length ? 'ok' : ok > 0 ? 'warn' : 'danger'} title={t('alerts.channel.confirmedHelp')}>
        {t('alerts.channel.confirmedCount', { ok, total: c.addresses.length })}
      </Badge>
    );
  }
  if (c.verified === false) {
    return (
      <Badge tone="warn" title={c.kind === 'telegram' ? t('alerts.channel.unverifiedTelegram') : t('alerts.channel.unverifiedHelp')}>
        {t('alerts.channel.unverified')}
      </Badge>
    );
  }
  return null;
}

const POLL_MS = 2000;

/**
 * Verify a Telegram group on the instance bot: a one-time /link command to
 * send in the group, then the channel is polled until it is verified.
 */
function TelegramVerifyDialog({ channel, onClose, onVerified }: { channel: NotificationChannel; onClose: () => void; onVerified: () => Promise<void> }) {
  const { t } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [link, setLink] = useState<TelegramChannelLink | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const done = useRef(onVerified);
  useEffect(() => {
    done.current = onVerified;
  });

  useEffect(() => {
    let live = true;
    setLink(null);
    setExpired(false);
    setError(null);
    a.telegramChannelLink(org.id, channel.id).then(
      (l) => live && setLink(l),
      (e: unknown) => live && setError(authErrorText(e, t)),
    );
    return () => {
      live = false;
    };
  }, [a, org.id, channel.id, attempt, t]);

  useEffect(() => {
    if (!link) return;
    let live = true;
    const expiresAt = Date.parse(link.expires_at);
    const id = window.setInterval(() => {
      if (Number.isFinite(expiresAt) && Date.now() > expiresAt) {
        window.clearInterval(id);
        setExpired(true);
        return;
      }
      a.getChannel(org.id, channel.id).then(
        (c) => {
          if (live && c.verified === true) {
            window.clearInterval(id);
            void done.current();
          }
        },
        () => undefined,
      );
    }, POLL_MS);
    return () => {
      live = false;
      window.clearInterval(id);
    };
  }, [a, org.id, channel.id, link]);

  return (
    <Dialog
      open
      title={t('alerts.channel.verifyTitle', { name: channel.name })}
      onClose={onClose}
      footer={
        <button type="button" className="btn" onClick={onClose}>
          {t('common.close')}
        </button>
      }
    >
      <div data-testid="telegram-verify">
        <ErrorBanner error={error} />
        {link ? (
          <>
            <ol className="steps small">
              <li>{t('alerts.channel.verifyStep1', { bot: `@${link.bot_username}` })}</li>
              <li>{t('alerts.channel.verifyStep2')}</li>
            </ol>
            <div className="secret-row">
              <code className="secret" data-testid="telegram-link-command">
                {link.command}
              </code>
              <CopyButton text={link.command} />
            </div>
            {expired ? (
              <p className="field-error" role="alert">
                {t('alerts.channel.verifyExpired')}{' '}
                <button type="button" className="btn btn-small" onClick={() => setAttempt((n) => n + 1)}>
                  {t('alerts.channel.newCode')}
                </button>
              </p>
            ) : (
              <p className="muted small" role="status">
                {t('alerts.channel.verifyWaiting')} · {t('notif.expires')} <RelativeTime value={link.expires_at} />
              </p>
            )}
          </>
        ) : error ? null : (
          <p className="muted small">{t('app.loading')}</p>
        )}
      </div>
    </Dialog>
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
  addresses,
  readOnly,
  caps,
  onClose,
  onSaved,
}: {
  id: string | null;
  initial: ChannelInput;
  secretSet: boolean | undefined;
  addresses: EmailAddressState[] | null;
  readOnly: boolean;
  caps: AlertCapabilities | null;
  onClose: () => void;
  onSaved: (saved: NotificationChannel | null) => Promise<void>;
}) {
  const { t, notify } = useApp();
  const { org } = useOrg();
  const a = useAlertsApi();
  const [v, setV] = useState<ChannelInput>(initial);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A 400 about the secret (not listed in ALERTS_SECRET_ORGS for this kind
  // and org, wrong prefix, ...) shows under its field, as the server words it.
  const [secretError, setSecretError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const allowPrivate = caps?.allow_private_urls === true;
  // Without capabilities (older server) assume the instance bot exists: the server decides.
  const instanceTelegram = caps?.telegram?.enabled !== false;
  const errors: ChannelErrors = touched ? validateChannel(v, allowPrivate, instanceTelegram) : {};
  const err = (k: keyof ChannelErrors) => (errors[k] ? t(`alerts.err.${errors[k]}` as MessageKey, { prefixes: kindPrefixes(v.kind).join(', ') }) : undefined);
  const cfg = v.config;
  const cs = (k: string) => (typeof cfg[k] === 'string' ? cfg[k] : '');
  const setCfg = (patch: Record<string, unknown>) => setV((x) => ({ ...x, config: { ...x.config, ...patch } }));
  const slackMode = cfg.mode === 'bot' ? 'bot' : 'webhook';

  const save = async () => {
    setTouched(true);
    setError(null);
    setSecretError(null);
    if (Object.keys(validateChannel(v, allowPrivate, instanceTelegram)).length > 0) return;
    setSaving(true);
    try {
      const body = channelBody(v);
      let saved: NotificationChannel;
      if (id) {
        // The kind of a channel does not change.
        saved = await a.updateChannel(org.id, id, { name: body.name, config: body.config, secret_env: body.secret_env, enabled: body.enabled });
      } else saved = await a.createChannel(org.id, body);
      notify(t('common.saved'));
      await onSaved(saved);
    } catch (e) {
      const msg = authErrorText(e, t);
      if (e instanceof ApiError && e.status === 400 && /secret_env|ALERTS_SECRET_ORGS/.test(e.message)) setSecretError(e.message);
      else setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const secretHelp = (): string => {
    const bound = ' ' + t('alerts.channel.envBound', { line: `${envExample(v.kind, slackMode)}=${v.kind}:${org.id}` });
    return secretHelpOf() + bound;
  };
  const secretHelpOf = (): string => {
    switch (v.kind) {
      case 'telegram':
        return instanceTelegram
          ? t('alerts.channel.envTelegramOptional', { example: envExample('telegram'), bot: caps?.telegram?.bot_username ? `@${caps.telegram.bot_username}` : t('alerts.channel.instanceBot') })
          : t('alerts.channel.envTelegram', { example: envExample('telegram') });
      case 'slack':
        return slackMode === 'bot' ? t('alerts.channel.envSlackBot', { example: envExample('slack', 'bot') }) : t('alerts.channel.envSlackWebhook', { example: envExample('slack', 'webhook') });
      case 'teams':
        return t('alerts.channel.envTeams', { example: envExample('teams') });
      case 'webhook':
        return t('alerts.channel.envWebhook', { example: envExample('webhook') });
      case 'a2a':
        return t('alerts.channel.envA2a', { example: envExample('a2a') });
      case 'pagerduty':
        return t('alerts.channel.envPagerduty', { example: envExample('pagerduty') });
      case 'opsgenie':
        return t('alerts.channel.envOpsgenie', { example: envExample('opsgenie') });
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
          {v.kind === 'telegram' && !onInstanceBot(v) ? (
            <Field label={t('alerts.channel.chatId')} help={t('alerts.channel.chatIdHelp')} error={err('chat_id')}>
              {(p) => <input {...p} className="mono" value={cs('chat_id')} placeholder="-1001234567890" onChange={(e) => setCfg({ chat_id: e.target.value })} />}
            </Field>
          ) : null}
          {v.kind === 'telegram' && onInstanceBot(v) ? (
            <p className="banner banner-info small" data-testid="telegram-instance-help">
              {t('alerts.channel.instanceBotHelp', { bot: caps?.telegram?.bot_username ? `@${caps.telegram.bot_username}` : t('alerts.channel.instanceBot') })}
              {initial.config.chat_id && initial.secret_env === v.secret_env ? (
                <>
                  {' '}
                  {t('alerts.channel.linkedChat', { chat: cs('chat_id') })}
                </>
              ) : null}
            </p>
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
            <>
              <Field label={t('alerts.channel.agentCard')} help={t('alerts.channel.agentCardHelp')} error={err('agent_card_url')}>
                {(p) => <input {...p} className="mono" type="url" value={cs('agent_card_url')} placeholder="https://agent.example.com" onChange={(e) => setCfg({ agent_card_url: e.target.value })} />}
              </Field>
              {allowPrivate ? (
                <Toggle label={t('alerts.channel.allowPrivate')} help={t('alerts.channel.allowPrivateHelp')} checked={cfg.allow_private === true} disabled={readOnly} onChange={(on) => setCfg({ allow_private: on })} />
              ) : null}
            </>
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
              <p className="muted small">
                {t('alerts.channel.optInHelp')}
                {caps?.email_daily_cap ? ` ${t('alerts.channel.dailyCap', { cap: caps.email_daily_cap })}` : ''}
              </p>
              {addresses && addresses.length > 0 ? <AddressList addresses={addresses} /> : null}
              <Field label={t('alerts.channel.lang')}>
                {(p) => (
                  <select {...p} value={cs('lang')} onChange={(e) => setCfg({ lang: e.target.value || undefined })}>
                    <option value="">{t('alerts.channel.langDefault')}</option>
                    <option value="en">English</option>
                    <option value="vi">Tiếng Việt</option>
                  </select>
                )}
              </Field>
            </>
          ) : null}
          {v.kind === 'teams' ? <p className="muted small">{t('alerts.channel.teamsHelp')}</p> : null}
          {v.kind === 'pagerduty' || v.kind === 'opsgenie' ? (
            <>
              <p className="muted small">{t(v.kind === 'pagerduty' ? 'alerts.channel.pagerdutyHelp' : 'alerts.channel.opsgenieHelp')}</p>
              <Field label={t('alerts.channel.region')}>
                {(p) => (
                  <select {...p} value={cs('region') || 'us'} disabled={readOnly} onChange={(e) => setCfg({ region: e.target.value })}>
                    <option value="us">{t('alerts.channel.regionUs')}</option>
                    <option value="eu">{t('alerts.channel.regionEu')}</option>
                  </select>
                )}
              </Field>
            </>
          ) : null}
          {v.kind !== 'email' ? (
            <Field label={t('alerts.channel.secretEnv')} help={secretHelp()} error={err('secret_env') ?? secretError ?? undefined}>
              {(p) => (
                <div className="input-with-badge">
                  <input
                    {...p}
                    className="mono"
                    value={v.secret_env ?? ''}
                    placeholder={envExample(v.kind, slackMode)}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(e) => {
                      setSecretError(null);
                      setV((x) => ({ ...x, secret_env: e.target.value.toUpperCase() }));
                    }}
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

/** The double opt-in state of each address of an email channel. */
function AddressList({ addresses }: { addresses: EmailAddressState[] }) {
  const { t } = useApp();
  return (
    <ul className="address-list" data-testid="email-addresses">
      {addresses.map((x) => (
        <li key={x.address}>
          <span className="mono small">{x.address}</span>
          {x.confirmed ? (
            <Badge tone="ok">{t('alerts.channel.addrConfirmed')}</Badge>
          ) : (
            <span className="badges">
              <Badge tone="warn">{t('alerts.channel.addrPending')}</Badge>
              {x.sent_at ? (
                <span className="muted small">
                  {t('alerts.channel.addrSent')} <RelativeTime value={x.sent_at} />
                </span>
              ) : null}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
