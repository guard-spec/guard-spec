// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The request log's tags: unscanned parts and personal data shown as
// labels, and the unscanned_content refusal as a readable reason.

import { describe, expect, it } from 'vitest';
import unscannedGo from '../../../internal/indirect/unscanned.go?raw';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import { translator } from '../i18n';
import { UNSCANNED_KINDS, UNSCANNED_MODES } from '../types';
import { auditTagLabel, blockReason, parseAuditTag, parseAuditTags, unscannedOf } from './auditTags';

const t = translator('en');

describe('audit tags', () => {
  it('reads unscanned and personal data tags, and keeps others as written', () => {
    expect(parseAuditTag('input:unscanned_image=2')).toEqual({ type: 'unscanned', kind: 'image', n: 2, raw: 'input:unscanned_image=2' });
    expect(parseAuditTag('input:pii_email=1')).toMatchObject({ type: 'pii', kind: 'email', n: 1 });
    expect(parseAuditTag('input:pii_tokenized_card=3')).toMatchObject({ type: 'piiProtected', verb: 'tokenized', kind: 'card', n: 3 });
    expect(parseAuditTag('input:unscanned_video=1')).toEqual({ type: 'other', raw: 'input:unscanned_video=1' });
    expect(parseAuditTag('output:email=1')).toEqual({ type: 'other', raw: 'output:email=1' });
    expect(parseAuditTags(null)).toEqual([]);
  });

  it('labels them in English and Vietnamese', () => {
    expect(auditTagLabel(t, parseAuditTag('input:unscanned_image=2'))).toBe('Unscanned image ×2');
    expect(auditTagLabel(t, parseAuditTag('input:unscanned_file=1'))).toBe('Unscanned file ×1');
    expect(auditTagLabel(t, parseAuditTag('input:unscanned_other=4'))).toBe('Unscanned part ×4');
    expect(auditTagLabel(t, parseAuditTag('input:pii_cccd=1'))).toBe('Personal data: CCCD ×1');
    expect(auditTagLabel(t, parseAuditTag('input:server_state=1'))).toBe('input:server_state=1');
    expect(auditTagLabel(translator('vi'), parseAuditTag('input:unscanned_audio=1'))).toBe('Âm thanh không quét ×1');
  });

  it('lists the unscanned parts of a row', () => {
    expect(unscannedOf({ pii_entities: ['input:pii_email=1', 'input:unscanned_image=2', 'input:unscanned_file=1'] })).toEqual([
      { kind: 'image', n: 2 },
      { kind: 'file', n: 1 },
    ]);
    expect(unscannedOf({})).toEqual([]);
  });

  it('names the unscanned_content refusal', () => {
    const row = { action: 'block', injection_label: null, rule_id: null, pii_entities: ['input:unscanned_image=1'] };
    expect(blockReason(row)).toBe('unscanned_content');
    expect(blockReason({ ...row, pii_entities: null, injection_label: 'unscanned_content' })).toBe('unscanned_content');
    // A rule or the detector refused it: the image is only a tag.
    expect(blockReason({ ...row, rule_id: 'r1' })).toBeNull();
    expect(blockReason({ ...row, injection_label: 'jailbreak' })).toBeNull();
    expect(blockReason({ ...row, action: 'allow' })).toBeNull();
    expect(t('audit.reason.unscanned_content')).toContain('block');
  });

  it('matches the backend kinds and modes (internal/indirect/unscanned.go)', () => {
    const kinds = /UnscannedKinds = \[\]string\{([^}]*)\}/.exec(unscannedGo)?.[1] ?? '';
    expect([...kinds.matchAll(/"([^"]+)"/g)].map((m) => m[1])).toEqual(UNSCANNED_KINDS);
    const modes = [...unscannedGo.matchAll(/Unscanned(?:Allow|Log|Block)\s*=\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(modes).toEqual(UNSCANNED_MODES);
  });

  it('has every unscanned label in both languages, translated', () => {
    const keys = [
      ...UNSCANNED_KINDS.map((k) => `audit.tag.unscanned.${k}`),
      ...UNSCANNED_MODES.flatMap((m) => [`guard.unscanned.${m}`, `guard.unscanned.${m}Help`]),
      'guard.unscanned',
      'guard.unscanned.default',
      'guard.unscanned.defaultHelp',
      'guard.unscanned.help',
      'guard.unscanned.extract',
      'audit.reason.unscanned_content',
    ] as const;
    const EN: Record<string, string | undefined> = en;
    const VI: Record<string, string | undefined> = vi;
    for (const k of keys) {
      expect(EN[k]?.trim(), `en ${k}`).toBeTruthy();
      expect(VI[k]?.trim(), `vi ${k}`).toBeTruthy();
      expect(VI[k], `vi ${k} translated`).not.toBe(EN[k]);
    }
    expect(en['guard.unscanned.defaultHelp']).toContain('UNSCANNED_PARTS');
  });
});
