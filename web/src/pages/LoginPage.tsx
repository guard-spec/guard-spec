// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { useState, type FormEvent, type ReactNode } from 'react';
import { ErrorBanner, Field } from '../components/ui';
import { errorText, useApp } from '../context';

export function LoginPage({ onLogin, expired, controls }: { onLogin: (token: string) => void; expired: boolean; controls: ReactNode }) {
  const { api, t } = useApp();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.login(email, password));
    } catch (err) {
      setError(t('login.failed', { error: errorText(err) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login" id="main">
      <form className="card login-card" onSubmit={submit} aria-labelledby="login-title">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" className="brand-shield" />
            <path d="m10 16 4 4 8-9" className="brand-check" />
          </svg>
          <div>
            <strong>{t('app.title')}</strong>
            <span className="muted">{t('app.subtitle')}</span>
          </div>
        </div>
        <h1 id="login-title">{t('login.title')}</h1>
        {expired && !error ? <div className="banner banner-info">{t('login.expired')}</div> : null}
        <ErrorBanner error={error} />
        <Field label={t('login.email')}>
          {(p) => <input {...p} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />}
        </Field>
        <Field label={t('login.password')}>
          {(p) => (
            <input {...p} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          )}
        </Field>
        <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
          {t('login.submit')}
        </button>
        <div className="login-controls">{controls}</div>
      </form>
    </main>
  );
}
