// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { en } from '../i18n/en';
import { vi } from '../i18n/vi';
import type { ConditionNode } from '../types';
import { FALLBACK_SCHEMA } from './schema';
import { ruleFromTemplate, ruleTemplates } from './templates';
import { conditionText } from './conditionText';
import { fieldTypesOf } from './schema';
import { hasErrors, validateCondition, type Problem } from './validate';
import type { Upstream } from '../types';

const keys = (ps: Problem[]) => ps.map((p) => `${p.severity}:${p.key}`);
const leaf = (field: string, operator: string, value: unknown): ConditionNode => ({ combinator: 'and', rules: [{ field, operator, value }] });

describe('condition validation', () => {
  const v = (n: ConditionNode, threshold?: number) => validateCondition(n, FALLBACK_SCHEMA, { injectionThreshold: threshold });

  it('accepts what the server accepts', () => {
    expect(v(leaf('injection.score', '>=', '0.7'))).toEqual([]);
    expect(v(leaf('request.tokens', '>', 8000))).toEqual([]);
    expect(v(leaf('anomaly.has_bidi', '=', 'true'))).toEqual([]);
    expect(v(leaf('injection.category', 'in', ['jailbreak', 'prompt_extraction']))).toEqual([]);
    expect(v(leaf('injection.category', '=', ''))).toEqual([]);
    expect(v(leaf('request.model', 'beginsWith', 'gpt-4'))).toEqual([]);
    expect(v(leaf('scores.l2', '>=', '0'))).toEqual([]);
  });

  it('finds what the server refuses, as errors', () => {
    expect(keys(v({ combinator: 'and', rules: [] }))).toEqual(['error:cond.empty']);
    expect(keys(v(leaf('', '=', 'x')))).toEqual(['error:cond.noField']);
    expect(keys(v(leaf('toxicity.score', '>', '0.5')))).toEqual(['error:cond.unknownField']);
    expect(keys(v(leaf('anomaly.has_bidi', '>', 'true')))).toEqual(['error:cond.badOperator']);
    expect(keys(v(leaf('injection.score', '>=', '')))).toEqual(['error:cond.emptyValue']);
    expect(keys(v(leaf('injection.score', '>=', 'high')))).toEqual(['error:cond.notNumber']);
    expect(keys(v(leaf('injection.score', '>=', '0,7')))).toEqual(['error:cond.notNumber']);
    expect(keys(v(leaf('request.tokens', '>', '10.5')))).toEqual(['error:cond.notInt']);
    expect(keys(v(leaf('mcp.is_tool_response', '=', 'yes')))).toEqual(['error:cond.notBool']);
    expect(keys(v(leaf('injection.category', 'in', ' , ')))).toEqual(['error:cond.emptyList']);
    expect(keys(v(leaf('request.model', 'contains', '')))).toEqual(['error:cond.emptyValue']);
    expect(hasErrors(v(leaf('injection.score', '>=', 'high')))).toBe(true);
  });

  it('warns about conditions that cannot do what they seem to', () => {
    expect(keys(v(leaf('injection.score', '>', '1.5')))).toEqual(['warning:cond.range']);
    expect(keys(v(leaf('scores.l3', '<', '-2')))).toEqual(['warning:cond.range']);
    // BENIGN is upper case.
    expect(keys(v(leaf('injection.label', '!=', 'benign')))).toEqual(['warning:cond.unknownValue']);
    expect(keys(v(leaf('injection.category', 'in', 'jailbreak, typo')))).toEqual(['warning:cond.unknownValue']);
    // The detectors block at the threshold before the rules run.
    expect(keys(v(leaf('injection.score', '>=', '0.9')))).toEqual(['warning:cond.aboveThreshold']);
    expect(keys(v(leaf('injection.score', '>=', '0.75'), 0.7))).toEqual(['warning:cond.aboveThreshold']);
    expect(keys(v(leaf('injection.score', '<', '0.9')))).toEqual([]);
    expect(keys(v(leaf('anomaly.score', '>=', '0.6')))).toEqual(['warning:cond.aboveThreshold']);
    expect(hasErrors(v(leaf('injection.score', '>', '1.5')))).toBe(false);
  });

  it('checks the personal-data fields as the server does', () => {
    expect(v(leaf('input.pii.count', '>', '0'))).toEqual([]);
    expect(v(leaf('input.pii.kinds', 'contains', 'card'))).toEqual([]);
    expect(v(leaf('input.pii.kinds', 'in', 'email'))).toEqual([]);
    expect(keys(v(leaf('input.pii.count', '>', '0.5')))).toEqual(['error:cond.notInt']);
    expect(keys(v(leaf('input.pii.count', '>=', '-1')))).toEqual(['warning:cond.range']);
    expect(keys(v(leaf('input.pii.kinds', '=', 'email')))).toEqual(['error:cond.badOperator']);
    // One value: the server refuses a list of them.
    expect(keys(v(leaf('input.pii.kinds', 'in', ['email', 'card'])))).toEqual(['error:cond.emptyValue']);
    expect(keys(v(leaf('input.pii.kinds', 'contains', '')))).toEqual(['error:cond.emptyValue']);
    expect(keys(v(leaf('input.pii.kinds', 'contains', 'name')))).toEqual(['warning:cond.unknownValue']);
    expect(conditionText(leaf('input.pii.kinds', 'in', 'cccd'), fieldTypesOf(FALLBACK_SCHEMA))).toBe('"cccd" in input.pii.kinds');
  });

  it('keeps the builder ids, so the builder can mark the row', () => {
    const tree = { combinator: 'and', id: 'g1', rules: [{ id: 'r1', field: 'injection.score', operator: '>=', value: 'x' }] } as unknown as ConditionNode;
    expect(v(tree)[0]?.id).toBe('r1');
  });

  it('has its messages in both languages, with the same parameters', () => {
    const all = ['cond.empty', 'cond.noField', 'cond.unknownField', 'cond.badOperator', 'cond.emptyValue', 'cond.notNumber', 'cond.notInt', 'cond.notBool', 'cond.emptyList', 'cond.range', 'cond.unknownValue', 'cond.aboveThreshold'] as const;
    for (const k of all) {
      const params = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
      expect(params(vi[k]), k).toEqual(params(en[k]));
    }
  });
});

describe('rule templates', () => {
  const up = (name: string, enabled = true) => ({ id: name, name, base_url: 'https://x', model: '', api_key_env: '', timeout_ms: 1000, enabled }) as Upstream;

  it('produce conditions the server accepts, without warnings', () => {
    for (const tpl of ruleTemplates([up('main'), up('safe')], 'main')) {
      expect(validateCondition(tpl.condition, FALLBACK_SCHEMA), tpl.id).toEqual([]);
      expect(en[tpl.name]).toBeTruthy();
      expect(vi[tpl.desc]).toBeTruthy();
    }
  });

  it('read as the expected expressions', () => {
    const types = fieldTypesOf(FALLBACK_SCHEMA);
    const text = Object.fromEntries(ruleTemplates([up('main'), up('safe')], 'main').map((t) => [t.id, conditionText(t.condition, types)]));
    expect(text).toEqual({
      blockInjection: 'injection.score >= 0.7 && injection.label != "BENIGN"',
      logTools: 'mcp.is_tool_response == true && indirect.score >= 0.5',
      routeSuspicious: 'injection.score >= 0.5',
      blockHidden: 'anomaly.has_tag_chars == true || anomaly.has_bidi == true',
    });
  });

  it('offer routing only to another enabled upstream', () => {
    expect(ruleTemplates([up('main')], 'main').map((t) => t.id)).not.toContain('routeSuspicious');
    expect(ruleTemplates([up('main'), up('off', false)], 'main').map((t) => t.id)).not.toContain('routeSuspicious');
    const route = ruleTemplates([up('main'), up('safe')], 'main').find((t) => t.id === 'routeSuspicious');
    expect(route?.target).toBe('safe');
    // Without a default upstream (the gateway's own), any enabled upstream is an alternative.
    expect(ruleTemplates([up('main')], undefined).find((t) => t.id === 'routeSuspicious')?.target).toBe('main');
  });

  it('make independent rules', () => {
    const [tpl] = ruleTemplates([], undefined);
    if (!tpl) throw new Error('no template');
    const a = ruleFromTemplate(tpl, 'a');
    const b = ruleFromTemplate(tpl, 'b');
    expect(a.key).not.toBe(b.key);
    expect(a.condition).not.toBe(tpl.condition);
    expect(a.route_target).toBeUndefined();
    const route = ruleTemplates([up('main'), up('safe')], 'main').find((t) => t.id === 'routeSuspicious');
    if (!route) throw new Error('no route template');
    expect(ruleFromTemplate(route, 'r')).toMatchObject({ action: 'route', route_target: 'safe' });
  });
});
