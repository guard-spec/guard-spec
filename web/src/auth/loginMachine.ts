// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The steps of signing in (identity contract §1 and §2): credentials or the
// SSO callback, then maybe a 2FA code or a forced 2FA enrollment, then the
// session. The mfa_token lives only in this state (memory), never in storage
// or the URL.

import type { LoginResponse, TotpSetup } from '../types';

export type LoginStep =
  | { step: 'credentials' }
  /** Exchanging the one-time code of #/auth/callback. */
  | { step: 'callback'; code: string }
  | { step: 'mfa'; mfaToken: string; methods: ('totp' | 'recovery')[]; recovery: boolean }
  | { step: 'enroll'; mfaToken: string; setup: TotpSetup | null }
  /** Recovery codes of a forced enrollment, shown once before the session starts. */
  | { step: 'codes'; token: string; codes: string[] }
  | { step: 'done'; token: string };

export type LoginEvent =
  | { type: 'response'; response: LoginResponse }
  | { type: 'setup'; setup: TotpSetup }
  | { type: 'enrolled'; codes: string[]; token?: string }
  | { type: 'acknowledged' }
  | { type: 'toggleRecovery' }
  | { type: 'restart' };

export function initialLogin(callbackCode: string | null): LoginStep {
  return callbackCode ? { step: 'callback', code: callbackCode } : { step: 'credentials' };
}

/** The next step for a response of /auth/login, /auth/mfa/verify or /auth/oidc/exchange. */
export function stepFor(r: LoginResponse): LoginStep {
  // Read loosely: the wire may carry false flags or extra fields.
  const o = r as { token?: unknown; mfa_required?: unknown; mfa_enroll_required?: unknown; mfa_token?: unknown; methods?: unknown };
  const mfaToken = typeof o.mfa_token === 'string' ? o.mfa_token : '';
  if (o.mfa_enroll_required === true && mfaToken) return { step: 'enroll', mfaToken, setup: null };
  if (o.mfa_required === true && mfaToken) {
    const listed = Array.isArray(o.methods) ? o.methods.filter((m): m is 'totp' | 'recovery' => m === 'totp' || m === 'recovery') : [];
    return { step: 'mfa', mfaToken, methods: listed.length > 0 ? listed : ['totp', 'recovery'], recovery: false };
  }
  if (typeof o.token === 'string' && o.token !== '') return { step: 'done', token: o.token };
  throw new Error('unexpected sign-in response');
}

export function loginReducer(s: LoginStep, e: LoginEvent): LoginStep {
  switch (e.type) {
    case 'response':
      return stepFor(e.response);
    case 'setup':
      return s.step === 'enroll' ? { ...s, setup: e.setup } : s;
    case 'enrolled':
      if (s.step !== 'enroll') return s;
      // Without a session token the enrollment cannot finish the sign-in: start over.
      return e.token ? { step: 'codes', token: e.token, codes: e.codes } : { step: 'credentials' };
    case 'acknowledged':
      return s.step === 'codes' ? { step: 'done', token: s.token } : s;
    case 'toggleRecovery':
      return s.step === 'mfa' && s.methods.includes('recovery') ? { ...s, recovery: !s.recovery } : s;
    case 'restart':
      return { step: 'credentials' };
  }
}

/** A TOTP code is 6 digits; a recovery code is letters and digits with an optional dash. */
export function normalizeCode(raw: string, recovery: boolean): string {
  const v = raw.trim();
  return recovery ? v.toLowerCase().replace(/\s+/g, '') : v.replace(/\s+/g, '');
}

export function isTotpCode(v: string): boolean {
  return /^\d{6}$/.test(v);
}

/** Reads the one-time code (or an error) of /ui/#/auth/callback?code=… */
export function parseCallbackHash(hash: string): { code: string | null; error: string | null } | null {
  const m = /^#\/auth\/callback(?:\?(.*))?$/.exec(hash);
  if (!m) return null;
  const q = new URLSearchParams(m[1] ?? '');
  return { code: q.get('code'), error: q.get('error') };
}
