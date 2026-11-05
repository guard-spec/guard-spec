// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Sign-in (identity contract §1, §2): email and password or an SSO provider,
// then a 2FA code or a forced 2FA enrollment. The SSO callback lands on
// /ui/#/auth/callback?code=…; the code is exchanged once and removed from the
// address bar.

import { ArrowLeft, KeyRound, LogIn, ShieldCheck } from 'lucide-react';
import { useEffect, useReducer, useState, type FormEvent } from 'react';
import { authErrorText } from '../auth/errors';
import { initialLogin, loginReducer, normalizeCode, parseCallbackHash, stepFor, type LoginStep } from '../auth/loginMachine';
import { BrandMark } from '../components/BrandMark';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnroll } from '../components/TotpEnroll';
import { ErrorBanner, Field, Loading } from '../components/ui';
import { useApp } from '../context';
import { clearHash } from '../router';
import { Preferences } from '../shell/Preferences';
import type { LoginProvider, LoginResponse } from '../types';

function readCallback(callback: boolean): { code: string | null; error: string | null } {
  if (!callback || typeof window === 'undefined') return { code: null, error: null };
  const r = parseCallbackHash(window.location.hash) ?? { code: null, error: null };
  clearHash(); // the one-time code is not left in the address bar or history
  return r;
}

function ProviderMark({ p }: { p: LoginProvider }) {
  if (p.type === 'google') {
    return (
      <span className="provider-mark provider-google" aria-hidden="true">
        G
      </span>
    );
  }
  return <KeyRound size={16} aria-hidden="true" />;
}

export function LoginPage({
  onLogin,
  expired,
  callback = false,
  initial,
}: {
  onLogin: (token: string) => void;
  expired: boolean;
  callback?: boolean;
  /** Continue from a login answer obtained elsewhere (an accepted invite). */
  initial?: LoginResponse;
}) {
  const { api, t } = useApp();
  const [cb] = useState(() => readCallback(callback));
  const [step, dispatch] = useReducer(loginReducer, null, (): LoginStep => (initial ? stepFor(initial) : initialLogin(cb.code)));
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(cb.error ? authErrorText(cb.error, t) : null);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<LoginProvider[]>([]);

  // SSO buttons; a control plane without /auth/providers shows none.
  useEffect(() => {
    let live = true;
    api.listLoginProviders().then(
      (ps) => live && setProviders(ps),
      () => live && setProviders([]),
    );
    return () => {
      live = false;
    };
  }, [api]);

  useEffect(() => {
    if (step.step !== 'callback') return;
    let live = true;
    api.exchangeOidcCode(step.code).then(
      (r) => live && dispatch({ type: 'response', response: r }),
      (e: unknown) => {
        if (!live) return;
        setError(t('login.failed', { error: authErrorText(e, t) }));
        dispatch({ type: 'restart' });
      },
    );
    return () => {
      live = false;
    };
  }, [api, step, t]);

  useEffect(() => {
    if (step.step === 'done') onLogin(step.token);
  }, [step, onLogin]);

  const enrollToken = step.step === 'enroll' && !step.setup ? step.mfaToken : null;
  useEffect(() => {
    if (!enrollToken) return;
    let live = true;
    api.setupTotp(enrollToken).then(
      (setup) => live && dispatch({ type: 'setup', setup }),
      (e: unknown) => {
        if (!live) return;
        setError(authErrorText(e, t));
        dispatch({ type: 'restart' });
      },
    );
    return () => {
      live = false;
    };
  }, [api, enrollToken, t]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        dispatch({ type: 'response', response: await api.signIn(email, password) });
        setPassword('');
      } catch (err) {
        setError(t('login.failed', { error: authErrorText(err, t) }));
      }
    });
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    if (step.step !== 'mfa') return;
    const value = normalizeCode(code, step.recovery);
    void run(async () => {
      try {
        dispatch({ type: 'response', response: await api.verifyMfa(step.mfaToken, value) });
        setCode('');
      } catch (err) {
        setError(authErrorText(err, t));
      }
    });
  };

  const confirmEnroll = (value: string) => {
    if (step.step !== 'enroll') return;
    void run(async () => {
      try {
        const r = await api.confirmTotp(value, step.mfaToken);
        dispatch({ type: 'enrolled', codes: r.recovery_codes, token: r.token });
      } catch (err) {
        setError(authErrorText(err, t));
      }
    });
  };

  const back = (
    <button
      type="button"
      className="btn btn-link btn-icon-text"
      onClick={() => {
        setError(null);
        setCode('');
        dispatch({ type: 'restart' });
      }}
    >
      <ArrowLeft size={14} aria-hidden="true" />
      <span>{t('login.back')}</span>
    </button>
  );

  let body;
  switch (step.step) {
    case 'callback':
    case 'done':
      body = (
        <>
          <h1 id="login-title">{t('login.title')}</h1>
          <Loading />
        </>
      );
      break;
    case 'mfa':
      body = (
        <form onSubmit={submitCode} aria-labelledby="login-title">
          <h1 id="login-title">{t('login.mfaTitle')}</h1>
          <p className="muted">{step.recovery ? t('login.recoveryHelp') : t('login.mfaHelp')}</p>
          <ErrorBanner error={error} />
          <Field label={step.recovery ? t('login.recoveryCode') : t('mfa.code')}>
            {(p) => (
              <input
                {...p}
                className="mono code-input"
                inputMode={step.recovery ? 'text' : 'numeric'}
                autoComplete="one-time-code"
                required
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            )}
          </Field>
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {t('login.verify')}
          </button>
          <div className="login-links">
            {step.methods.includes('recovery') ? (
              <button
                type="button"
                className="btn btn-link"
                onClick={() => {
                  setCode('');
                  dispatch({ type: 'toggleRecovery' });
                }}
              >
                {step.recovery ? t('login.useTotp') : t('login.useRecovery')}
              </button>
            ) : null}
            {back}
          </div>
        </form>
      );
      break;
    case 'enroll':
      body = (
        <div aria-labelledby="login-title">
          <h1 id="login-title">{t('login.enrollTitle')}</h1>
          <p className="muted">{t('login.enrollHelp')}</p>
          <ErrorBanner error={error} />
          {step.setup ? <TotpEnroll setup={step.setup} onConfirm={confirmEnroll} busy={busy} /> : <Loading />}
          <div className="login-links">{back}</div>
        </div>
      );
      break;
    case 'codes':
      body = (
        <div aria-labelledby="login-title">
          <h1 id="login-title">{t('mfa.codesTitle')}</h1>
          <RecoveryCodes codes={step.codes} />
          <button type="button" className="btn btn-primary btn-block" onClick={() => dispatch({ type: 'acknowledged' })}>
            {t('mfa.savedContinue')}
          </button>
        </div>
      );
      break;
    default:
      body = (
        <>
          <h1 id="login-title">{t('login.title')}</h1>
          {expired && !error ? <div className="banner banner-info">{t('login.expired')}</div> : null}
          <ErrorBanner error={error} />
          <form onSubmit={submitPassword} aria-labelledby="login-title">
            <Field label={t('login.email')}>
              {(p) => <input {...p} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />}
            </Field>
            <Field label={t('login.password')}>
              {(p) => (
                <input {...p} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              )}
            </Field>
            <button type="submit" className="btn btn-primary btn-block btn-icon-text" disabled={busy}>
              <LogIn size={16} aria-hidden="true" />
              <span>{t('login.submit')}</span>
            </button>
          </form>
          {providers.length > 0 ? (
            <div className="sso" data-testid="sso-buttons">
              <div className="divider">
                <span>{t('login.or')}</span>
              </div>
              {providers.map((p) => (
                <a key={p.id} className="btn btn-block btn-icon-text sso-button" href={api.oidcStartUrl(p.id, '/ui/')}>
                  <ProviderMark p={p} />
                  <span>{t('login.continueWith', { name: p.display_name })}</span>
                </a>
              ))}
            </div>
          ) : null}
        </>
      );
  }

  return (
    <main className="login" id="main">
      <div className="login-card card">
        <div className="brand">
          <BrandMark size={32} />
          <span className="brand-text">
            <strong>{t('app.title')}</strong>
            <span className="muted">{t('app.subtitle')}</span>
          </span>
        </div>
        {body}
        <div className="login-controls">
          <Preferences />
        </div>
      </div>
      <p className="login-foot muted small">
        <ShieldCheck size={14} aria-hidden="true" /> {t('login.foot')}
      </p>
    </main>
  );
}
