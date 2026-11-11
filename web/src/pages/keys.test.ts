// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import type { OrgSecurity } from '../types';
import { expiryIn, validCidr } from './KeysPage';
import { securityBody, validateSecurity } from './SecurityPage';

const base: OrgSecurity = { require_mfa: false, sso_satisfies_mfa: false, allowed_login_methods: null, domain_join: [], session_lifetime_hours: 12 };

describe('API key policy', () => {
  it('checks allowed addresses before sending them', () => {
    for (const ok of ['203.0.113.0/24', '198.51.100.7', '2001:db8::1', '2001:db8::/32', '::1', '10.0.0.0/8 ']) expect(validCidr(ok), ok).toBe(true);
    for (const bad of ['', 'nope', '300.1.1.1', '10.0.0.0/33', '2001:db8::/129', '10.0.0.0/8/1', 'a:b:c:d:e:f:g:h']) expect(validCidr(bad), bad).toBe(false);
  });

  it('prefills the expiry at the maximum lifetime', () => {
    const now = new Date(2026, 10, 11, 9, 30);
    expect(expiryIn(30, now)).toBe('2026-12-11T09:30');
  });

  it('validates and sends the maximum key lifetime', () => {
    expect(validateSecurity({ ...base, api_key_max_lifetime_days: null })).toEqual([]);
    expect(validateSecurity({ ...base, api_key_max_lifetime_days: 90 })).toEqual([]);
    expect(validateSecurity({ ...base, api_key_max_lifetime_days: 0 })).toEqual(['keyLifetime']);
    expect(validateSecurity({ ...base, api_key_max_lifetime_days: 3651 })).toEqual(['keyLifetime']);
    expect(securityBody(base, false)).toHaveProperty('api_key_max_lifetime_days', null);
    expect(securityBody({ ...base, api_key_max_lifetime_days: 90 }, false)).toHaveProperty('api_key_max_lifetime_days', 90);
  });

  it('has every key message in both languages', () => {
    for (const key of Object.keys(en).filter((k) => k.startsWith('keys.') || k.startsWith('sec.apiKeys') || k.startsWith('sec.keyMax'))) {
      expect(vi, key).toHaveProperty(key);
    }
  });
});
