// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { methodLabel } from './auth/methods';
import { describeUserAgent } from './auth/userAgent';
import { headerClass } from './components/DataTable';
import { formatDate, formatDateTime, formatRelative, localeOf } from './dates';
import { fitViewport } from './flow/layout';
import { translator } from './i18n';
import { computeStats, normLabel, ruleNames } from './pages/dashboard';
import { detailsText } from './pages/ActivityPage';
import { panelPosition } from './shell/Shell';
import type { AuditRow, Policy } from './types';

describe('labels and names', () => {
  it('compares detector labels in any case', () => {
    expect(normLabel('BENIGN')).toBe('benign');
    expect(normLabel(' Jailbreak ')).toBe('jailbreak');
    expect(normLabel('')).toBeNull();
    expect(normLabel(null)).toBeNull();
    const row = (label: string): AuditRow => ({
      id: label,
      model: null,
      action: 'allow',
      rule_id: null,
      injection_label: label,
      injection_score: 0,
      anomaly_score: 0,
      had_tag_chars: false,
      had_bidi: false,
      latency_ms: 1,
      created_at: '2026-11-04T08:00:00Z',
    });
    expect(computeStats([row('BENIGN'), row('benign'), row('JAILBREAK'), row('jailbreak')]).topLabels).toEqual([{ label: 'jailbreak', count: 2 }]);
  });

  it('names rules by id', () => {
    const p = { id: 'p', name: 'Block injection', rules: [{ id: 'r1', name: 'High score', action: 'block', condition: { combinator: 'and', rules: [] } }] } as unknown as Policy;
    expect(ruleNames([p]).get('r1')).toEqual({ rule: 'High score', policy: 'Block injection' });
  });

  it('shows sign-in methods by provider name, never as an id', () => {
    const t = translator('en');
    const providers = [
      { id: 'g1', type: 'google' as const, display_name: 'Google Workspace' },
      { id: 'k1', type: 'oidc' as const, display_name: 'Keycloak' },
    ];
    expect(methodLabel('password', providers, t)).toBe('Password');
    expect(methodLabel('google', providers, t)).toBe('Google Workspace');
    expect(methodLabel('oidc:k1', providers, t)).toBe('Keycloak');
    expect(methodLabel('oidc:9b6cac98-141b-4641-9026-c1a2a86b9627', providers, t)).toBe('SSO');
  });

  it('names a session device from its user agent', () => {
    expect(describeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36')).toEqual({
      browser: 'Chrome',
      os: 'macOS',
      client: false,
    });
    expect(describeUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0')).toMatchObject({
      browser: 'Edge',
      os: 'Windows',
    });
    expect(describeUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1')).toMatchObject({
      browser: 'Safari',
      os: 'iOS',
    });
    expect(describeUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0')).toMatchObject({ browser: 'Firefox', os: 'Linux' });
    expect(describeUserAgent('node')).toEqual({ browser: null, os: null, client: true });
    expect(describeUserAgent('curl/8.7.1').client).toBe(true);
    expect(describeUserAgent(null).client).toBe(true);
  });
});

describe('activity details', () => {
  it('leaves ids to the tooltip', () => {
    const d = { role: 'admin', invite_id: 'c107b1db-3b22-43e7-8153-e7a41a4839a9', ok: true };
    expect(detailsText(d, true)).toBe('role: admin · ok: true');
    expect(detailsText(d)).toContain('invite_id: c107b1db');
    expect(detailsText(null)).toBe('');
  });
});

describe('dates in the UI language', () => {
  const at = '2026-11-04T12:40:00Z';
  it('formats by locale', () => {
    expect(localeOf('vi')).toBe('vi-VN');
    expect(formatDateTime(at, 'vi-VN')).toMatch(/thg 11/);
    expect(formatDateTime(at, 'vi-VN')).not.toMatch(/AM|PM/);
    expect(formatDateTime(at, 'en-US')).toMatch(/Nov 4, 2026/);
    expect(formatDate(at, 'en-US')).toBe('Nov 4, 2026');
    expect(formatDateTime(null)).toBe('—');
    expect(formatDateTime('not a date')).toBe('not a date');
  });

  it('says how long ago', () => {
    const now = Date.parse(at);
    expect(formatRelative(now - 5 * 60_000, now, 'en-US')).toBe('5 minutes ago');
    expect(formatRelative(now - 3 * 86_400_000, now, 'en-US')).toBe('3 days ago');
    expect(formatRelative(now - 2000, now, 'en-US')).toBe('now');
    expect(formatRelative(now - 3_600_000, now, 'vi-VN')).toMatch(/giờ trước/);
  });
});

describe('layout helpers', () => {
  it('keeps value classes off table headers', () => {
    expect(headerClass('mono small')).toBeUndefined();
    expect(headerClass('row-actions')).toBe('row-actions');
    expect(headerClass('nowrap mono col-url')).toBe('nowrap col-url');
  });

  it('opens the flow fitted to view, centred', () => {
    const v = fitViewport({ x: 0, y: 0, width: 2000, height: 1000 }, { width: 1000, height: 600 });
    expect(v.zoom).toBeCloseTo(0.476, 2); // height-bound: (600 - 48) / 1000 < (1000 - 48) / 2000
    expect(v.y).toBeCloseTo((600 - 1000 * v.zoom) / 2, 5);
    expect(fitViewport({ x: 0, y: 0, width: 100, height: 100 }, { width: 1000, height: 600 }).zoom).toBe(1);
    expect(fitViewport({ x: 0, y: 0, width: 100000, height: 100 }, { width: 1000, height: 600 }).zoom).toBe(0.2);
  });

  it('places the profile menu inside the viewport', () => {
    expect(panelPosition({ left: 10, top: 850 }, 1440, 900)).toEqual({ left: 10, bottom: 56, width: 288 });
    expect(panelPosition({ left: 200, top: 700 }, 300, 720)).toEqual({ left: 8, bottom: 26, width: 284 });
  });
});
