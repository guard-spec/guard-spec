// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi as viMessages } from '../i18n/vi';
import type { UpstreamInput } from '../types';
import { DASH_WINDOWS, share, volumeBars } from './dashboard';
import { ApiError } from '../api';
import { authErrorText, CODES } from '../auth/errors';
import { translator } from '../i18n';
import { validateIdp, validIssuer } from './IdentityProvidersPage';
import { providerLabel, slugName, validateProvider } from './providerCatalog';
import { securityBody, validateSecurity } from './SecurityPage';

const base: UpstreamInput = {
  name: 'main',
  base_url: 'https://api.openai.com/v1',
  model: '',
  api_key_env: 'UPSTREAM_KEY_MAIN',
  timeout_ms: 30000,
  enabled: true,
};

describe('model provider validation', () => {
  it('accepts a valid provider', () => {
    expect(validateProvider({ ...base, models: ['gpt-4o'], default_model: 'gpt-4o', headers: { 'OpenAI-Organization': 'org_x' }, retries: 1 })).toEqual({});
  });

  it('refuses secret headers, a default outside the allowed models and bad numbers', () => {
    expect(validateProvider({ ...base, headers: { Authorization: 'x' } }).headers).toBe('header');
    expect(validateProvider({ ...base, headers: { 'X-Thing': 'sk-abcdef' } }).headers).toBe('header');
    expect(validateProvider({ ...base, models: ['a'], default_model: 'b' }).default_model).toBe('defaultModel');
    expect(validateProvider({ ...base, retries: 9 }).retries).toBe('number');
    expect(validateProvider({ ...base, timeout_ms: 10 }).timeout_ms).toBe('number');
    expect(validateProvider({ ...base, name: 'Bad Name', base_url: 'ftp://x', api_key_env: 'key' })).toMatchObject({ name: 'name', base_url: 'url', api_key_env: 'env' });
  });

  it('makes a name from a display name', () => {
    expect(slugName('Google Gemini')).toBe('google-gemini');
    expect(slugName('  Mô hình Việt  ')).toBe('mo-hinh-viet');
  });
});

describe('identity provider and security validation', () => {
  it('requires an https issuer and an OIDC_SECRET_ variable name, never a secret', () => {
    const ok = {
      type: 'google' as const,
      display_name: 'Google',
      issuer: 'https://accounts.google.com',
      client_id: 'id',
      client_secret_env: 'OIDC_SECRET_GOOGLE',
      scopes: ['openid'],
      allowed_domains: [],
      auto_provision: false,
      enabled: true,
    };
    expect(validateIdp(ok)).toEqual({});
    expect(validateIdp({ ...ok, issuer: 'http://x', client_secret_env: 'GOCSPX-secret' })).toEqual({ issuer: true, client_secret_env: true });
  });

  it('accepts http issuers only on loopback hosts, like the control plane', () => {
    expect(validIssuer('https://accounts.google.com')).toBe(true);
    expect(validIssuer('http://localhost:9000/realms/x')).toBe(true);
    expect(validIssuer('http://127.0.0.1:5556')).toBe(true);
    expect(validIssuer('http://[::1]:5556')).toBe(true);
    expect(validIssuer('http://idp.example.com')).toBe(false);
    expect(validIssuer('https://idp.example.com?x=1')).toBe(false);
    expect(validIssuer('not a url')).toBe(false);
  });

  it('sends allowed_login_methods only when it was changed, null for unrestricted', () => {
    const s = { require_mfa: true, sso_satisfies_mfa: false, allowed_login_methods: ['password', 'google'], domain_join: [], session_lifetime_hours: 12 };
    expect(securityBody(s, false)).not.toHaveProperty('allowed_login_methods');
    expect(securityBody(s, true).allowed_login_methods).toEqual(['password', 'google']);
    expect(securityBody({ ...s, allowed_login_methods: null }, true)).toHaveProperty('allowed_login_methods', null);
    expect(validateSecurity({ ...s, allowed_login_methods: null })).toEqual([]);
  });

  it('names providers by the catalog, then the built-in presets', () => {
    expect(providerLabel([], 'openai_compatible')).toBe('OpenAI-compatible');
    expect(providerLabel([{ id: 'vllm', display_name: 'vLLM (GPU)', default_base_url: '', key_required: false, known_models: [] }], 'vllm')).toBe('vLLM (GPU)');
    expect(providerLabel([], 'something_new')).toBe('something_new');
    expect(providerLabel([], undefined)).toBe('—');
  });

  it('translates error codes before the server text', () => {
    const t = translator('vi');
    const err = new ApiError(409, 'the last owner cannot be demoted', { error: 'the last owner cannot be demoted', code: 'last_owner' });
    expect(authErrorText(err, t)).toBe(viMessages['authErr.last_owner']);
    expect(authErrorText('mfa_token_invalid', translator('en'))).toBe(en['authErr.mfa_token_invalid']);
    expect(authErrorText(new ApiError(400, 'x', { error: { code: 'model_not_allowed' } }), translator('en'))).toBe(en['authErr.model_not_allowed']);
    expect(authErrorText(new ApiError(500, 'internal error', { error: 'internal error' }), t)).toBe('internal error');
    for (const code of ['invalid_state', 'email_not_verified', 'exchange_failed', 'provider_error', 'invalid_nonce', 'invalid_token', 'sso_unavailable', 'account_exists', 'domain_not_allowed', 'would_lock_out', 'login_method_not_allowed', 'last_owner', 'not_sole_authority', 'mfa_locked', 'model_not_allowed', 'mfa_token_invalid', 'link_expired', 'link_wrong_user', 'identity_in_use']) {
      expect(CODES[code], code).toBeDefined();
    }
  });

  it('checks the org security policy', () => {
    const s = { require_mfa: true, sso_satisfies_mfa: false, allowed_login_methods: ['password'], domain_join: [], session_lifetime_hours: 12 };
    expect(validateSecurity(s)).toEqual([]);
    expect(validateSecurity({ ...s, allowed_login_methods: [], session_lifetime_hours: 0, domain_join: [{ domain: 'not a domain', provider_id: '', role: 'viewer' }] })).toEqual([
      'methods',
      'lifetime',
      'domain',
    ]);
  });
});

describe('dashboard', () => {
  it('turns the server series into bars', () => {
    const { bars, max } = volumeBars({
      series: [
        { start: '2026-11-04T07:00:00Z', count: 3, blocked: 1 },
        { start: '2026-11-04T08:00:00Z', count: 0, blocked: 0 },
      ],
    });
    expect(bars).toEqual([
      { start: Date.UTC(2026, 10, 4, 7), count: 3, blocked: 1 },
      { start: Date.UTC(2026, 10, 4, 8), count: 0, blocked: 0 },
    ]);
    expect(max).toBe(3);
    // No traffic: bars at height 0, never a division by 0.
    expect(volumeBars({ series: [] }).max).toBe(1);
  });

  it('computes shares and offers 24h first', () => {
    expect(share(1, 4)).toBe(0.25);
    expect(share(0, 0)).toBe(0);
    expect(DASH_WINDOWS[0]).toBe('24h');
    for (const w of DASH_WINDOWS) expect(en[`dash.window.${w}`]).toBeTruthy();
  });
});

describe('i18n', () => {
  it('has every key in both languages, non-empty', () => {
    expect(Object.keys(viMessages).sort()).toEqual(Object.keys(en).sort());
    for (const [k, v] of Object.entries(viMessages)) expect(v, k).not.toBe('');
  });

  it('uses sentence case for navigation labels', () => {
    for (const [k, v] of Object.entries(en)) {
      if (!k.startsWith('nav.') && !k.startsWith('navg.')) continue;
      const words = v.split(' ').slice(1);
      // Later words are lowercase, except acronyms such as API.
      for (const w of words) expect(w === w.toLowerCase() || w === w.toUpperCase(), `${k}: ${v}`).toBe(true);
    }
  });

  it('keeps the {placeholders} of each message in Vietnamese', () => {
    const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const k of Object.keys(en) as (keyof typeof en)[]) expect(ph(viMessages[k]), k).toEqual(ph(en[k]));
  });
});
