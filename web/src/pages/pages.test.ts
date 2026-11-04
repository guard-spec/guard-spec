// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi as viMessages } from '../i18n/vi';
import type { AuditRow, UpstreamInput } from '../types';
import { computeStats, quantile } from './dashboard';
import { validateIdp } from './IdentityProvidersPage';
import { slugName, validateProvider } from './providerCatalog';
import { validateSecurity } from './SecurityPage';

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

describe('dashboard stats', () => {
  const row = (action: string, label: string, latency: number, minutesAgo: number): AuditRow => ({
    id: `${action}-${minutesAgo}`,
    model: 'gpt-4o',
    action,
    rule_id: null,
    injection_label: label,
    injection_score: 0,
    anomaly_score: 0,
    had_tag_chars: false,
    had_bidi: false,
    latency_ms: latency,
    created_at: new Date(Date.UTC(2026, 10, 4, 8) - minutesAgo * 60_000).toISOString(),
  });

  it('computes rates, latency percentiles and volume buckets', () => {
    const rows = [row('allow', 'benign', 100, 0), row('block', 'injection', 30, 10), row('block', 'jailbreak', 40, 20), row('route', 'injection', 500, 30)];
    const s = computeStats(rows, 4);
    expect(s.count).toBe(4);
    expect(s.blocked).toBe(2);
    expect(s.blockRate).toBe(0.5);
    expect(s.byAction[0]).toEqual({ action: 'block', count: 2 });
    expect(s.topLabels).toEqual([
      { label: 'injection', count: 2 },
      { label: 'jailbreak', count: 1 },
    ]);
    expect(s.p50).toBe(40);
    expect(s.p99).toBe(500);
    expect(s.volume).toHaveLength(4);
    expect(s.volume.reduce((a, b) => a + b.count, 0)).toBe(4);
  });

  it('handles no rows', () => {
    expect(computeStats([])).toMatchObject({ count: 0, blockRate: 0, p50: null, volume: [] });
    expect(quantile([], 0.5)).toBeNull();
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
