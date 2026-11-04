// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// My account → Notifications (contract §3, §6): personal Telegram, Slack and
// email channels, and per channel whether it is on and from which severity.
// Options the instance cannot deliver (GET /v1/alerts/capabilities) are hidden.

import { BellRing, ExternalLink, Link2, Send, Unlink } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { authErrorText } from '../auth/errors';
import { Badge, NotAvailable } from '../components/DataTable';
import { ConfirmDialog, CopyButton, ErrorBanner, Loading, RelativeTime } from '../components/ui';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import { prefs as localPrefs, session } from '../session';
import { alertsApi } from './api';
import { PERSONAL_KINDS, SEVERITIES, type AlertCapabilities, type ChannelLink, type NotificationPref, type PersonalKind, type Severity, type TelegramStart } from './types';

/** The personal kinds this instance can deliver. */
export function availableKinds(caps: AlertCapabilities | null): PersonalKind[] {
  if (!caps) return [];
  return PERSONAL_KINDS.filter((k) => (k === 'telegram' ? caps.telegram?.enabled === true : k === 'slack' ? caps.slack_bot === true : caps.smtp === true));
}

/** Prefs for every kind shown, filling in the defaults (off until linked, warning and up). */
export function fillPrefs(kinds: PersonalKind[], stored: NotificationPref[]): NotificationPref[] {
  return kinds.map((k) => stored.find((p) => p.channel_kind === k) ?? { channel_kind: k, enabled: k === 'email', min_severity: 'warning' });
}

const POLL_MS = 2000;

export function NotificationSettings() {
  const { api, t, notify, me } = useApp();
  const a = useMemo(() => alertsApi(api), [api]);
  const orgId = session.orgId();
  const orgName = localPrefs.recentOrgs().find((o) => o.id === orgId)?.name ?? null;
  const [caps, setCaps] = useState<AlertCapabilities | null | 'none'>(null);
  const [links, setLinks] = useState<ChannelLink[]>([]);
  const [prefs, setPrefs] = useState<NotificationPref[] | null>(null);
  const [saved, setSaved] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [telegram, setTelegram] = useState<TelegramStart | null>(null);
  const [expired, setExpired] = useState(false);
  const [unlinking, setUnlinking] = useState<PersonalKind | null>(null);
  const [slackBusy, setSlackBusy] = useState(false);

  const loadLinks = useCallback(async () => {
    try {
      const l = await a.channelLinks();
      setLinks(l);
      return l;
    } catch {
      return null;
    }
  }, [a]);

  useEffect(() => {
    let live = true;
    a.capabilities().then(
      (c) => live && setCaps(c),
      () => live && setCaps('none'),
    );
    void loadLinks();
    return () => {
      live = false;
    };
  }, [a, loadLinks]);

  const kinds = useMemo(() => availableKinds(caps === 'none' ? null : caps), [caps]);

  useEffect(() => {
    if (!orgId || caps === null || caps === 'none') return;
    let live = true;
    a.getPrefs(orgId).then(
      (p) => {
        if (!live) return;
        const filled = fillPrefs(kinds, p);
        setPrefs(filled);
        setSaved(JSON.stringify(filled));
      },
      () => {
        if (!live) return;
        const filled = fillPrefs(kinds, []);
        setPrefs(filled);
        setSaved(JSON.stringify(filled));
      },
    );
    return () => {
      live = false;
    };
  }, [a, orgId, caps, kinds]);

  // Linking Telegram: poll the links until the bot reports the /start, or the code expires.
  useEffect(() => {
    if (!telegram) return;
    let live = true;
    const expiresAt = Date.parse(telegram.expires_at);
    const id = window.setInterval(() => {
      if (Number.isFinite(expiresAt) && Date.now() > expiresAt) {
        window.clearInterval(id);
        setTelegram(null);
        setExpired(true);
        return;
      }
      void loadLinks().then((l) => {
        if (live && l?.some((x) => x.kind === 'telegram')) {
          window.clearInterval(id);
          setTelegram(null);
          notify(t('notif.telegramLinked'));
        }
      });
    }, POLL_MS);
    return () => {
      live = false;
      window.clearInterval(id);
    };
  }, [telegram, loadLinks, notify, t]);

  if (caps === null) return <Section><Loading /></Section>;
  if (caps === 'none') {
    return (
      <Section>
        <NotAvailable feature={t('notif.title')} compact />
      </Section>
    );
  }

  const link = (k: PersonalKind) => links.find((l) => l.kind === k) ?? null;
  const startTelegram = async () => {
    setError(null);
    setExpired(false);
    try {
      setTelegram(await a.startTelegram());
    } catch (e) {
      setError(authErrorText(e, t));
    }
  };
  const linkSlack = async () => {
    setError(null);
    setSlackBusy(true);
    try {
      await a.linkSlack();
      await loadLinks();
      notify(t('notif.slackLinked'));
    } catch (e) {
      setError(t('notif.slackFailed', { error: authErrorText(e, t) }));
    } finally {
      setSlackBusy(false);
    }
  };
  const setPref = (k: PersonalKind, patch: Partial<NotificationPref>) => setPrefs((ps) => (ps ?? []).map((p) => (p.channel_kind === k ? { ...p, ...patch } : p)));
  const savePrefs = async () => {
    if (!orgId || !prefs) return;
    setSaving(true);
    setError(null);
    try {
      await a.putPrefs(orgId, prefs);
      setSaved(JSON.stringify(prefs));
      notify(t('notif.prefsSaved'));
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setSaving(false);
    }
  };
  const dirty = prefs !== null && JSON.stringify(prefs) !== saved;
  const botName = caps.telegram?.bot_username;

  return (
    <Section>
      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <h3>{t('notif.channels')}</h3>
      <p className="muted small">{t('notif.inAppAlways')}</p>
      {kinds.length === 0 ? <p className="muted">{t('notif.noneAvailable')}</p> : null}
      <ul className="list-rows" data-testid="notif-links">
        {kinds.includes('telegram') ? (
          <li>
            <div className="cell-stack">
              <strong>
                <Send size={14} aria-hidden="true" /> Telegram
              </strong>
              <span className="muted small">
                {link('telegram') ? t('notif.linkedTo', { address: link('telegram')?.address ?? '' }) : botName ? t('notif.telegramHelp', { bot: `@${botName}` }) : t('notif.notLinked')}
              </span>
            </div>
            {link('telegram') ? (
              <UnlinkButton onClick={() => setUnlinking('telegram')} label={t('notif.unlinkOf', { kind: 'Telegram' })} />
            ) : telegram ? null : (
              <button type="button" className="btn btn-small btn-icon-text" onClick={() => void startTelegram()}>
                <Link2 size={14} aria-hidden="true" />
                <span>{t('notif.linkTelegram')}</span>
              </button>
            )}
          </li>
        ) : null}
        {telegram ? (
          <li className="telegram-link" data-testid="telegram-link">
            <div className="cell-stack">
              <span>{t('notif.telegramSteps')}</span>
              <span className="secret-row">
                <code className="secret" data-testid="telegram-code">
                  /start {telegram.code}
                </code>
                <CopyButton text={`/start ${telegram.code}`} />
              </span>
              <a className="btn btn-primary btn-icon-text" href={telegram.deep_link} target="_blank" rel="noopener noreferrer" data-testid="telegram-deeplink">
                <ExternalLink size={14} aria-hidden="true" />
                <span>{t('notif.openTelegram')}</span>
              </a>
              <span className="muted small" role="status">
                {t('notif.waiting')} · {t('notif.expires')} <RelativeTime value={telegram.expires_at} />
              </span>
            </div>
            <button type="button" className="btn btn-small" onClick={() => setTelegram(null)}>
              {t('common.cancel')}
            </button>
          </li>
        ) : null}
        {expired ? (
          <li>
            <span className="field-error" role="alert">
              {t('notif.codeExpired')}
            </span>
          </li>
        ) : null}
        {kinds.includes('slack') ? (
          <li>
            <div className="cell-stack">
              <strong>Slack</strong>
              <span className="muted small">{link('slack') ? t('notif.linkedTo', { address: link('slack')?.address ?? '' }) : t('notif.slackHelp', { email: me?.email ?? '' })}</span>
            </div>
            {link('slack') ? (
              <UnlinkButton onClick={() => setUnlinking('slack')} label={t('notif.unlinkOf', { kind: 'Slack' })} />
            ) : (
              <button type="button" className="btn btn-small btn-icon-text" disabled={slackBusy} onClick={() => void linkSlack()}>
                <Link2 size={14} aria-hidden="true" />
                <span>{t('notif.linkSlack')}</span>
              </button>
            )}
          </li>
        ) : null}
        {kinds.includes('email') ? (
          <li>
            <div className="cell-stack">
              <strong>{t('alerts.kind.email')}</strong>
              <span className="muted small">{t('notif.emailTo', { email: link('email')?.address ?? me?.email ?? '' })}</span>
            </div>
            <Badge tone="ok">{t('notif.emailReady')}</Badge>
          </li>
        ) : null}
      </ul>

      {kinds.length > 0 ? (
        <>
          <h3>{orgName ? t('notif.prefsFor', { org: orgName }) : t('notif.prefs')}</h3>
          {!orgId ? (
            <p className="muted small">{t('notif.pickOrg')}</p>
          ) : prefs === null ? (
            <Loading />
          ) : (
            <>
              <table className="settings-table prefs-table" data-testid="notif-prefs">
                <thead>
                  <tr>
                    <th scope="col">{t('alerts.delivery.channel')}</th>
                    <th scope="col">{t('alerts.enabled')}</th>
                    <th scope="col">{t('notif.minSeverity')}</th>
                  </tr>
                </thead>
                <tbody>
                  {prefs.map((p) => {
                    const label = t(`alerts.kind.${p.channel_kind}` as MessageKey);
                    const unlinked = p.channel_kind !== 'email' && !link(p.channel_kind);
                    return (
                      <tr key={p.channel_kind}>
                        <th scope="row">
                          {label}
                          {unlinked ? <span className="muted small"> · {t('notif.notLinkedShort')}</span> : null}
                        </th>
                        <td>
                          <label className="switch">
                            <input
                              type="checkbox"
                              role="switch"
                              checked={p.enabled}
                              aria-label={t('notif.enabledOf', { kind: label })}
                              onChange={(e) => setPref(p.channel_kind, { enabled: e.target.checked })}
                            />
                            <span className="switch-track" aria-hidden="true" />
                          </label>
                        </td>
                        <td>
                          <select aria-label={t('notif.minSeverityOf', { kind: label })} value={p.min_severity} onChange={(e) => setPref(p.channel_kind, { min_severity: e.target.value as Severity })}>
                            {SEVERITIES.map((s) => (
                              <option key={s} value={s}>
                                {t(`alerts.sev.${s}` as MessageKey)}
                              </option>
                            ))}
                          </select>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <p className="muted small">{t('notif.prefsHelp')}</p>
              <button type="button" className="btn btn-primary" disabled={!dirty || saving} onClick={() => void savePrefs()}>
                {saving ? t('common.saving') : t('notif.savePrefs')}
              </button>
            </>
          )}
        </>
      ) : null}

      <ConfirmDialog
        open={unlinking !== null}
        title={t('account.unlink')}
        body={t('notif.confirmUnlink', { kind: unlinking ? t(`alerts.kind.${unlinking}` as MessageKey) : '' })}
        confirmLabel={t('account.unlink')}
        danger
        onClose={() => setUnlinking(null)}
        onConfirm={async () => {
          if (!unlinking) return;
          try {
            await a.unlink(unlinking);
            await loadLinks();
            notify(t('notif.unlinked'));
          } catch (e) {
            notify(authErrorText(e, t), 'error');
          }
          setUnlinking(null);
        }}
      />
    </Section>
  );
}

function Section({ children }: { children: ReactNode }) {
  const { t } = useApp();
  return (
    <section className="card" aria-labelledby="notif-title" data-testid="notification-settings">
      <h2 id="notif-title">
        <BellRing size={16} aria-hidden="true" /> {t('notif.title')}
      </h2>
      {children}
    </section>
  );
}

function UnlinkButton({ onClick, label }: { onClick: () => void; label: string }) {
  const { t } = useApp();
  return (
    <button type="button" className="btn btn-small btn-icon-text" aria-label={label} onClick={onClick}>
      <Unlink size={14} aria-hidden="true" />
      <span>{t('account.unlink')}</span>
    </button>
  );
}
