// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Policy templates (PII, OTP/KYC, banking) and sample sentences in the
// simulator (RF-a1dbafea U3).

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import { conditionText } from './conditionText';
import { FALLBACK_SCHEMA, fieldTypesOf } from './schema';
import { formFromVars, simVars } from './Simulator';
import { freePolicyName, POLICY_TEMPLATES, policyTemplateRules } from './templates';
import { validateCondition } from './validate';

describe('policy templates', () => {
  it('produce rules the server accepts, without warnings, named in both languages', () => {
    expect(POLICY_TEMPLATES.map((p) => p.id)).toEqual(['pii', 'otpKyc', 'banking']);
    for (const tpl of POLICY_TEMPLATES) {
      for (const k of [tpl.name, tpl.desc]) expect(vi[k], k).not.toBe(en[k]);
      for (const r of tpl.rules) {
        expect(validateCondition(r.condition, FALLBACK_SCHEMA), `${tpl.id} ${r.name}`).toEqual([]);
        expect(vi[r.name], r.name).not.toBe(en[r.name]);
      }
    }
  });

  it('read as the expected expressions', () => {
    const types = fieldTypesOf(FALLBACK_SCHEMA);
    const otp = POLICY_TEMPLATES.find((p) => p.id === 'otpKyc');
    expect(otp?.rules.map((r) => conditionText(r.condition, types))).toEqual([
      'injection.score >= 0.5 && (injection.category == "data_exfiltration" || injection.category == "prompt_extraction")',
      '"cccd" in input.pii.kinds && "phone" in input.pii.kinds',
      '"image" in input.unscanned.kinds',
    ]);
  });

  it('become editable rules, each with its own key and a copy of the condition', () => {
    const tpl = POLICY_TEMPLATES[0];
    if (!tpl) throw new Error('no template');
    const a = policyTemplateRules(tpl, (k) => en[k]);
    const b = policyTemplateRules(tpl, (k) => en[k]);
    expect(a.map((r) => r.name)).toEqual(['Block payment card numbers', 'Block citizen ID numbers (CCCD)', 'Log other personal data']);
    expect(new Set([...a, ...b].map((r) => r.key)).size).toBe(6);
    expect(a[0]?.condition).not.toBe(tpl.rules[0]?.condition);
  });

  it('take a free name', () => {
    const taken = new Set(['Banking', 'Banking 2']);
    expect(freePolicyName('Banking', (n) => taken.has(n))).toBe('Banking 3');
    expect(freePolicyName('PII', (n) => taken.has(n))).toBe('PII');
  });
});

describe('sample sentences', () => {
  it('fill the simulator form with the scored fields, which convert back unchanged', () => {
    const vars = { 'scores.l1': 0.912345, 'scores.l2': -1, 'injection.label': 'jailbreak', 'anomaly.has_bidi': false, 'input.pii.kinds': ['email', 'phone'], 'input.pii.count': 2 };
    const form = formFromVars(vars);
    expect(form).toEqual({ 'scores.l1': '0.912', 'scores.l2': '-1', 'injection.label': 'jailbreak', 'anomaly.has_bidi': 'false', 'input.pii.kinds': 'email, phone', 'input.pii.count': '2' });
    expect(simVars(FALLBACK_SCHEMA, form)).toEqual({ ...vars, 'scores.l1': 0.912 });
  });
});
