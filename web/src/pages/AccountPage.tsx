// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// My account (identity contract §1, §2): profile, password, two-factor
// authentication with recovery codes, linked sign-in identities and active
// sessions.

import { KeyRound, Link2, Monitor, ShieldCheck, ShieldOff, Unlink } from 'lucide-react';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, isNotFound } from '../api';
import { authErrorText } from '../auth/errors';
import { isTotpCode } from '../auth/loginMachine';
import { Badge, DataTable, NotAvailable, type Column } from '../components/DataTable';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnroll } from '../components/TotpEnroll';
import { usePaged } from '../components/usePaged';
import { ConfirmDialog, Dialog, ErrorBanner, Field, formatTime, Loading, PageHeader } from '../components/ui';
import { errorText, nonEmpty, useApp } from '../context';
import type { LoginProvider, SessionInfo, TotpSetup } from '../types';

export default function AccountPage() {
  const { t, me } = useApp();
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    // GET /auth/me runs at sign-in; give it a moment before saying it is missing.
    const id = window.setTimeout(() => setLoaded(true), 1500);
    return () => window.clearTimeout(id);
  }, []);
  return (
    <div className="narrow">
      <PageHeader title={t('account.title')} help={t('account.help')} />
      {me ? (
        <>
          <Profile />
          <PasswordCard />
          <MfaCard />
          <IdentitiesCard />
          <SessionsCard />
        </>
      ) : loaded ? (
        <div className="card">
          <NotAvailable feature={t('account.title')} />
        </div>
      ) : (
        <Loading />
      )}
    </div>
  );
}

function Profile() {
  const { t, me } = useApp();
  if (!me) return null;
  return (
    <section className="card" aria-labelledby="profile-title">
      <h2 id="profile-title">{t('account.profile')}</h2>
      <div className="profile-head">
        <span className="avatar avatar-lg" aria-hidden="true">
          {(nonEmpty(me.display_name) ?? me.email).slice(0, 1).toUpperCase()}
        </span>
        <div className="cell-stack">
          <strong>{nonEmpty(me.display_name) ?? me.email}</strong>
          <span className="muted">{me.email}</span>
          <span className="badges">
            {me.is_instance_admin ? <Badge tone="accent">{t('profile.instanceAdmin')}</Badge> : null}
            <Badge tone={me.mfa_enabled ? 'ok' : 'warn'}>{me.mfa_enabled ? t('account.mfaOn') : t('account.mfaOff')}</Badge>
          </span>
        </div>
      </div>
    </section>
  );
}

function PasswordCard() {
  const { api, t, notify, me } = useApp();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!me) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next.length < 12) {
      setError(t('account.passwordShort'));
      return;
    }
    if (next !== confirm) {
      setError(t('account.passwordMismatch'));
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent('');
      setNext('');
      setConfirm('');
      notify(t('account.passwordChanged'));
    } catch (err) {
      setError(isNotFound(err) ? t('na.title') : errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card" aria-labelledby="pw-title">
      <h2 id="pw-title">
        <KeyRound size={16} aria-hidden="true" /> {t('account.password')}
      </h2>
      {me.has_password ? (
        <form onSubmit={submit}>
          <ErrorBanner error={error} />
          <input type="text" autoComplete="username" value={me.email} readOnly hidden />
          <Field label={t('account.currentPassword')}>
            {(p) => <input {...p} type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />}
          </Field>
          <div className="form-grid">
            <Field label={t('account.newPassword')} help={t('account.passwordHelp')}>
              {(p) => <input {...p} type="password" autoComplete="new-password" minLength={12} required value={next} onChange={(e) => setNext(e.target.value)} />}
            </Field>
            <Field label={t('account.confirmPassword')}>
              {(p) => <input {...p} type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
            </Field>
          </div>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t('account.changePassword')}
          </button>
        </form>
      ) : (
        <p className="muted">{t('account.ssoOnly')}</p>
      )}
    </section>
  );
}

/** A dialog asking for a current 2FA code before a sensitive change. */
function CodeDialog({
  open,
  title,
  body,
  confirmLabel,
  danger,
  onSubmit,
  onClose,
}: {
  open: boolean;
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  onSubmit: (code: string) => Promise<string | null>;
  onClose: () => void;
}) {
  const { t } = useApp();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const close = () => {
    setCode('');
    setError(null);
    onClose();
  };
  const submit = async () => {
    const v = code.replace(/\s+/g, '');
    if (!isTotpCode(v) && v.length < 8) {
      setError(t('mfa.codeInvalid'));
      return;
    }
    const err = await onSubmit(v);
    if (err) setError(err);
    else {
      setCode('');
      setError(null);
    }
  };
  return (
    <Dialog
      open={open}
      title={title}
      onClose={close}
      footer={
        <>
          <button type="button" className="btn" onClick={close}>
            {t('common.cancel')}
          </button>
          <button type="button" className={danger ? 'btn btn-danger' : 'btn btn-primary'} onClick={() => void submit()}>
            {confirmLabel}
          </button>
        </>
      }
    >
      <p>{body}</p>
      <ErrorBanner error={error} />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label={t('account.codeOrRecovery')}>
          {(p) => <input {...p} className="mono code-input" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />}
        </Field>
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function MfaCard() {
  const { api, t, notify, me, reloadMe } = useApp();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<'disable' | 'regenerate' | null>(null);
  if (!me) return null;

  const start = async () => {
    setError(null);
    setBusy(true);
    try {
      setSetup(await api.setupTotp());
    } catch (e) {
      setError(isNotFound(e) ? t('na.title') : authErrorText(e, t));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async (code: string) => {
    setError(null);
    setBusy(true);
    try {
      const r = await api.confirmTotp(code);
      setSetup(null);
      setCodes(r.recovery_codes);
      notify(t('account.mfaEnabled'));
      await reloadMe();
    } catch (e) {
      setError(authErrorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="mfa-title">
      <h2 id="mfa-title">
        <ShieldCheck size={16} aria-hidden="true" /> {t('account.mfa')}
      </h2>
      <ErrorBanner error={error} />
      {codes ? (
        <>
          <h3>{t('mfa.codesTitle')}</h3>
          <RecoveryCodes codes={codes} />
          <button type="button" className="btn btn-primary" onClick={() => setCodes(null)}>
            {t('mfa.saved')}
          </button>
        </>
      ) : setup ? (
        <>
          <TotpEnroll setup={setup} onConfirm={(c) => void confirm(c)} busy={busy} />
          <button type="button" className="btn btn-link" onClick={() => setSetup(null)}>
            {t('common.cancel')}
          </button>
        </>
      ) : me.mfa_enabled ? (
        <>
          <p>
            <Badge tone="ok">{t('account.mfaOn')}</Badge> <span className="muted">{t('account.mfaOnHelp')}</span>
          </p>
          <div className="row-gap">
            <button type="button" className="btn" onClick={() => setDialog('regenerate')}>
              {t('account.regenerate')}
            </button>
            <button type="button" className="btn btn-danger btn-icon-text" onClick={() => setDialog('disable')}>
              <ShieldOff size={14} aria-hidden="true" />
              <span>{t('account.disableMfa')}</span>
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="muted">{t('account.mfaOffHelp')}</p>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void start()}>
            {t('account.enableMfa')}
          </button>
        </>
      )}
      <CodeDialog
        open={dialog === 'disable'}
        title={t('account.disableMfa')}
        body={t('account.disableMfaBody')}
        confirmLabel={t('account.disableMfa')}
        danger
        onClose={() => setDialog(null)}
        onSubmit={async (code) => {
          try {
            await api.disableMfa(code);
            setDialog(null);
            notify(t('account.mfaDisabled'));
            await reloadMe();
            return null;
          } catch (e) {
            if (e instanceof ApiError && e.status === 409) return t('authErr.mfa_required_by_org');
            return authErrorText(e, t);
          }
        }}
      />
      <CodeDialog
        open={dialog === 'regenerate'}
        title={t('account.regenerate')}
        body={t('account.regenerateBody')}
        confirmLabel={t('account.regenerate')}
        onClose={() => setDialog(null)}
        onSubmit={async (code) => {
          try {
            const r = await api.regenerateRecoveryCodes(code);
            setDialog(null);
            setCodes(r.recovery_codes);
            return null;
          } catch (e) {
            return authErrorText(e, t);
          }
        }}
      />
    </section>
  );
}

function IdentitiesCard() {
  const { api, t, notify, me, reloadMe } = useApp();
  const [providers, setProviders] = useState<LoginProvider[] | null>(null);
  const [unlinking, setUnlinking] = useState<LoginProvider | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.listLoginProviders().then(setProviders, () => setProviders([]));
  }, [api]);
  if (!me) return null;
  const linked = (p: LoginProvider) => me.identities.find((i) => i.provider === p.id || i.provider === p.type);
  return (
    <section className="card" aria-labelledby="ids-title">
      <h2 id="ids-title">
        <Link2 size={16} aria-hidden="true" /> {t('account.identities')}
      </h2>
      <p className="muted small">{t('account.identitiesHelp')}</p>
      <ErrorBanner error={error} />
      {providers === null ? <Loading /> : null}
      {providers?.length === 0 ? <p className="muted">{t('account.noProviders')}</p> : null}
      <ul className="list-rows">
        {(providers ?? []).map((p) => {
          const id = linked(p);
          return (
            <li key={p.id}>
              <div className="cell-stack">
                <strong>{p.display_name}</strong>
                <span className="muted small">{id ? t('account.linkedAs', { email: id.email }) : t('account.notLinked')}</span>
              </div>
              {id ? (
                <button type="button" className="btn btn-small btn-icon-text" onClick={() => setUnlinking(p)}>
                  <Unlink size={14} aria-hidden="true" />
                  <span>{t('account.unlink')}</span>
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-small btn-icon-text"
                  onClick={async () => {
                    setError(null);
                    try {
                      window.location.assign(await api.startLinkIdentity(p.id, '/ui/account'));
                    } catch (e) {
                      setError(isNotFound(e) ? t('na.title') : errorText(e));
                    }
                  }}
                >
                  <Link2 size={14} aria-hidden="true" />
                  <span>{t('account.link')}</span>
                </button>
              )}
            </li>
          );
        })}
      </ul>
      <ConfirmDialog
        open={unlinking !== null}
        title={t('account.unlink')}
        body={t('account.confirmUnlink', { name: unlinking?.display_name ?? '' })}
        confirmLabel={t('account.unlink')}
        danger
        onClose={() => setUnlinking(null)}
        onConfirm={async () => {
          if (!unlinking) return;
          try {
            await api.unlinkIdentity(unlinking.id);
            notify(t('account.unlinked'));
            await reloadMe();
          } catch (e) {
            notify(e instanceof ApiError && e.status === 409 ? t('account.lastMethod') : errorText(e), 'error');
          }
          setUnlinking(null);
        }}
      />
    </section>
  );
}

function SessionsCard() {
  const { api, t, notify } = useApp();
  const fetchPage = useCallback(() => api.listSessions(), [api]);
  const paged = usePaged<SessionInfo>(fetchPage);
  const [revoking, setRevoking] = useState<SessionInfo | null>(null);
  const columns: Column<SessionInfo>[] = [
    {
      key: 'device',
      header: t('account.device'),
      cell: (s) => (
        <div className="cell-stack">
          <span>
            <Monitor size={14} aria-hidden="true" /> {s.user_agent ?? '—'}
            {s.current ? <Badge tone="accent">{t('account.thisSession')}</Badge> : null}
          </span>
          <span className="muted small mono">{s.ip ?? ''}</span>
        </div>
      ),
    },
    { key: 'created', header: t('account.signedIn'), className: 'nowrap small', cell: (s) => formatTime(s.created_at) },
    { key: 'seen', header: t('account.lastSeen'), className: 'nowrap small', cell: (s) => formatTime(s.last_seen_at) },
    {
      key: 'actions',
      header: t('common.actions'),
      hiddenHeader: true,
      className: 'row-actions',
      cell: (s) =>
        s.current ? null : (
          <button type="button" className="btn btn-small btn-danger" onClick={() => setRevoking(s)}>
            {t('account.revoke')}
          </button>
        ),
    },
  ];
  return (
    <section className="card card-flush" aria-labelledby="sess-title">
      <h2 id="sess-title" className="card-pad">
        {t('account.sessions')}
      </h2>
      <DataTable columns={columns} paged={paged} rowKey={(s) => s.id} testId="sessions-table" feature={t('account.sessions')} />
      <ConfirmDialog
        open={revoking !== null}
        title={t('account.revoke')}
        body={t('account.confirmRevoke')}
        confirmLabel={t('account.revoke')}
        danger
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await api.revokeSession(revoking.id);
            await paged.reload();
          } catch (e) {
            notify(errorText(e), 'error');
          }
          setRevoking(null);
        }}
      />
    </section>
  );
}
