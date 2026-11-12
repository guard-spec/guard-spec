// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { translator } from '../i18n';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import { auditTagLabel, parseAuditTag } from './auditTags';
import { fieldChangeText, previousVersion } from './PolicyHistoryPage';

describe('policy history', () => {
  const t = translator('en');

  it('compares a version with the one before it', () => {
    const items = [{ version: 5 }, { version: 3 }, { version: 1 }];
    expect(previousVersion(items, 5)).toBe(3);
    expect(previousVersion(items, 3)).toBe(1);
    expect(previousVersion(items, 1)).toBeNull();
  });

  it('describes field changes in words, with project names and on/off', () => {
    const projectName = (id: string | null) => (id === 'p1' ? 'Billing bot' : 'Org-wide');
    expect(fieldChangeText(t, { field: 'enabled', from: true, to: false }, projectName)).toBe('Enabled: On → Off');
    expect(fieldChangeText(t, { field: 'project_id', from: null, to: 'p1' }, projectName)).toBe('Applies to: Org-wide → Billing bot');
    expect(fieldChangeText(t, { field: 'name', from: 'a', to: 'b' }, projectName)).toBe('Name: a → b');
    expect(fieldChangeText(t, { field: 'description', from: '', to: 'why' }, projectName)).toBe('Description: — → why');
  });

  it('reads a log-only policy tag and labels it in both languages', () => {
    const id = '3f10c338-54a6-4932-ae9e-e57924b940c9';
    const tag = parseAuditTag(`policy:would_block=${id}`);
    expect(tag).toEqual({ type: 'wouldDecide', action: 'block', ruleId: id, raw: `policy:would_block=${id}` });
    expect(auditTagLabel(t, tag)).toBe(en['audit.tag.wouldBlock']);
    expect(auditTagLabel(translator('vi'), tag)).toBe(vi['audit.tag.wouldBlock']);
    expect(parseAuditTag('policy:would_route=' + id)).toMatchObject({ type: 'wouldDecide', action: 'route' });
    expect(parseAuditTag('policy:would_redact=' + id)).toEqual({ type: 'other', raw: 'policy:would_redact=' + id });
  });

  it('has every history message in both languages', () => {
    for (const key of Object.keys(en).filter((k) => k.startsWith('history.') || k.startsWith('policy.logOnly'))) {
      expect(vi, key).toHaveProperty(key);
    }
  });
});
