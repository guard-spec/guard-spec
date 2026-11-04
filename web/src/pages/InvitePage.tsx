// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Accepting an invite: /ui/invite?token=… (public). POST /invites/accept
// answers like a login (N15), so a 2FA step or enrollment continues on the
// sign-in page.

import { UserPlus } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { authErrorText } from '../auth/errors';
import { ErrorBanner, Field } from '../components/ui';
import { useApp } from '../context';
import type { MessageKey } from '../i18n';
import { session } from '../session';
import { Preferences } from '../shell/Preferences';
import type { LoginResponse, Role } from '../types';
import { LoginPage } from './LoginPage';

/** Reads and strips the invite token from the address bar. */
function readToken(): string | null {
  const q = new URLSearchParams(window.location.search);
  const token = q.get('token');
  if (token !== null) {
    q.delete('token');
    const rest = q.toString();
    window.history.replaceState(null, '', window.location.pathname + (rest ? `?${rest}` : ''));
  }
  return token;
}

export function InvitePage({ onLogin }: { onLogin: (token: string) => void }) {
  const { api, t, notify } = useApp();
  const [token] = useState(readToken);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [next, setNext] = useState<LoginResponse | null>(null);

  if (next) return <LoginPage initial={next} expired={false} onLogin={onLogin} />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setError(null);
    if (password.length < 12) {
      setError(t('account.passwordShort'));
      return;
    }
    if (password !== confirm) {
      setError(t('account.passwordMismatch'));
      return;
    }
    setBusy(true);
    try {
      const r = await api.acceptInvite(token, password, name.trim());
      // Open the organization of the invite after sign-in.
      if (r.org_id) session.setOrgId(r.org_id);
      if (r.role) notify(t('invitePage.joined', { role: t(`org.role.${r.role satisfies Role}` as MessageKey) }));
      if ('token' in r && typeof r.token === 'string') onLogin(r.token);
      else setNext(r);
    } catch (err) {
      setError(authErrorText(err, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login" id="main">
      <div className="login-card card">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" className="brand-shield" />
            <path d="m10 16 4 4 8-9" className="brand-check" />
          </svg>
          <span className="brand-text">
            <strong>{t('app.title')}</strong>
            <span className="muted">{t('app.subtitle')}</span>
          </span>
        </div>
        <h1 id="invite-title">{t('invitePage.title')}</h1>
        {token ? (
          <form onSubmit={submit} aria-labelledby="invite-title">
            <p className="muted">{t('invitePage.help')}</p>
            <ErrorBanner error={error} />
            <Field label={t('account.displayName')}>
              {(p) => <input {...p} autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />}
            </Field>
            <Field label={t('login.password')} help={t('account.passwordHelp')}>
              {(p) => <input {...p} type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />}
            </Field>
            <Field label={t('account.confirmPassword')}>
              {(p) => <input {...p} type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
            </Field>
            <button type="submit" className="btn btn-primary btn-block btn-icon-text" disabled={busy}>
              <UserPlus size={16} aria-hidden="true" />
              <span>{t('invitePage.submit')}</span>
            </button>
          </form>
        ) : (
          <div className="banner banner-error" role="alert">
            {t('invitePage.noToken')}
          </div>
        )}
        <div className="login-controls">
          <Preferences />
        </div>
      </div>
    </main>
  );
}
