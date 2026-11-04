// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { LoginResponse } from '../types';
import { initialLogin, isTotpCode, loginReducer, normalizeCode, parseCallbackHash, stepFor, type LoginStep } from './loginMachine';

const respond = (s: LoginStep, response: LoginResponse) => loginReducer(s, { type: 'response', response });

describe('login state machine', () => {
  it('starts with credentials, or with the SSO code of the callback', () => {
    expect(initialLogin(null)).toEqual({ step: 'credentials' });
    expect(initialLogin('one-time')).toEqual({ step: 'callback', code: 'one-time' });
  });

  it('finishes on a session token', () => {
    expect(respond({ step: 'credentials' }, { token: 'tok', user: { email: 'a@b.c' } })).toEqual({ step: 'done', token: 'tok' });
  });

  it('asks for a code, toggles recovery, then finishes', () => {
    let s = respond({ step: 'credentials' }, { mfa_required: true, mfa_token: 'm1', methods: ['totp', 'recovery'] });
    expect(s).toEqual({ step: 'mfa', mfaToken: 'm1', methods: ['totp', 'recovery'], recovery: false });
    s = loginReducer(s, { type: 'toggleRecovery' });
    expect(s).toMatchObject({ recovery: true });
    s = respond(s, { token: 'tok' });
    expect(s).toEqual({ step: 'done', token: 'tok' });
  });

  it('does not offer recovery codes when the server does not list them', () => {
    const s = respond({ step: 'credentials' }, { mfa_required: true, mfa_token: 'm1', methods: ['totp'] });
    expect(loginReducer(s, { type: 'toggleRecovery' })).toMatchObject({ recovery: false });
  });

  it('defaults the methods when the server omits them', () => {
    expect(stepFor({ mfa_required: true, mfa_token: 'm' })).toMatchObject({ methods: ['totp', 'recovery'] });
  });

  it('runs a forced enrollment: setup, confirm, codes shown once, then the session', () => {
    let s = respond({ step: 'credentials' }, { mfa_enroll_required: true, mfa_token: 'e1' });
    expect(s).toEqual({ step: 'enroll', mfaToken: 'e1', setup: null });
    s = loginReducer(s, { type: 'setup', setup: { secret: 'JBSWY3DP', otpauth_url: 'otpauth://totp/x' } });
    expect(s).toMatchObject({ step: 'enroll', setup: { secret: 'JBSWY3DP' } });
    s = loginReducer(s, { type: 'enrolled', codes: ['aaaa-bbbb'], token: 'tok' });
    expect(s).toEqual({ step: 'codes', token: 'tok', codes: ['aaaa-bbbb'] });
    // The session starts only after the user saw the codes.
    s = loginReducer(s, { type: 'acknowledged' });
    expect(s).toEqual({ step: 'done', token: 'tok' });
  });

  it('starts over when enrollment ends without a session token', () => {
    const s = loginReducer({ step: 'enroll', mfaToken: 'e', setup: null }, { type: 'enrolled', codes: [] });
    expect(s).toEqual({ step: 'credentials' });
  });

  it('applies the same steps to the SSO exchange', () => {
    const s = respond({ step: 'callback', code: 'c' }, { mfa_required: true, mfa_token: 'm2' });
    expect(s).toMatchObject({ step: 'mfa', mfaToken: 'm2' });
  });

  it('ignores events of another step and restarts', () => {
    expect(loginReducer({ step: 'credentials' }, { type: 'acknowledged' })).toEqual({ step: 'credentials' });
    expect(loginReducer({ step: 'credentials' }, { type: 'setup', setup: { secret: 's', otpauth_url: 'u' } })).toEqual({ step: 'credentials' });
    expect(loginReducer({ step: 'mfa', mfaToken: 'm', methods: ['totp'], recovery: false }, { type: 'restart' })).toEqual({ step: 'credentials' });
  });

  it('refuses a response it does not understand', () => {
    expect(() => stepFor({} as LoginResponse)).toThrow(/unexpected/);
    expect(() => stepFor({ mfa_required: true, mfa_token: '' })).toThrow(/unexpected/);
  });

  it('normalizes codes', () => {
    expect(normalizeCode(' 123 456 ', false)).toBe('123456');
    expect(normalizeCode(' ABCD-EF12 ', true)).toBe('abcd-ef12');
    expect(isTotpCode('123456')).toBe(true);
    expect(isTotpCode('12345')).toBe(false);
    expect(isTotpCode('12345a')).toBe(false);
  });

  it('reads the callback hash', () => {
    expect(parseCallbackHash('#/auth/callback?code=abc')).toEqual({ code: 'abc', error: null });
    expect(parseCallbackHash('#/auth/callback?error=account_exists')).toEqual({ code: null, error: 'account_exists' });
    expect(parseCallbackHash('#/auth/callback')).toEqual({ code: null, error: null });
    expect(parseCallbackHash('#/flow')).toBeNull();
    expect(parseCallbackHash('')).toBeNull();
  });
});
